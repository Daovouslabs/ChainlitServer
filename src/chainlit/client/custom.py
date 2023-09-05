from typing import Dict, Any, Optional
import uuid
import os
import asyncio
import aiohttp
from python_graphql_client import GraphqlClient

from chainlit.client.base import MessageDict, UserDict
from starlette.datastructures import Headers
from chainlit.client.base import BaseDBClient, BaseAuthClient, PaginatedResponse, PageInfo
from chainlit.logger import logger
from chainlit.config import config
from chainlit.s3_utils import S3Client
import base64
from auth0.authentication.token_verifier import AsymmetricSignatureVerifier
from auth0.management import Auth0
from auth0.authentication import GetToken

CUSTOM_AUTH0_DOMAIN = os.environ.get("CUSTOM_AUTH0_DOMAIN")
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")

def parse_access_token(token):
    """
    Verify the token and its precedence

    :param token:
    """
    jwks_url = "https://{}/.well-known/jwks.json".format(CUSTOM_AUTH0_DOMAIN)
    sv = AsymmetricSignatureVerifier(jwks_url)
    return sv.verify_signature(token)

def get_access_token():
    get_token = GetToken(AUTH0_DOMAIN, AUTH0_CLIENT_ID, client_secret=AUTH0_CLIENT_SECRET)
    token = get_token.client_credentials('https://{}/api/v2/'.format(AUTH0_DOMAIN))
    mgmt_api_token = token['access_token']
    return mgmt_api_token


class GraphQLClient:
    def __init__(self):
        graphql_endpoint = config.graphql_url
        self.graphql_client = GraphqlClient(
            endpoint=graphql_endpoint
        )

    def query(self, query: str, variables: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a GraphQL query.

        :param query: The GraphQL query string.
        :param variables: A dictionary of variables for the query.
        :return: The response data as a dictionary.
        """
        var = {k: v for k, v in variables.items() if f'${k}' in query and v is not None}
        return self.graphql_client.execute_async(query=query, variables=var)

    def check_for_errors(self, response: Dict[str, Any], raise_error: bool = False):
        if "errors" in response:
            if raise_error:
                raise Exception(response["errors"][0])
            logger.error(response["errors"][0])
            return True
        return False

    def mutation(self, mutation: str, variables: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a GraphQL mutation.

        :param mutation: The GraphQL mutation string.
        :param variables: A dictionary of variables for the mutation.
        :return: The response data as a dictionary.
        """
        var = {k: v for k, v in variables.items() if f'${k}' in mutation and v is not None}
        return self.graphql_client.execute_async(query=mutation, variables=var)


class CustomAuthClient(BaseAuthClient, GraphQLClient):

    def __init__(self, 
        handshake_headers: Optional[Dict[str, str]] = None,
        request_headers: Optional[Headers] = None,
    ):
        access_token = None

        if handshake_headers:
            access_token = handshake_headers.get("HTTP_AUTHORIZATION")
        elif request_headers:
            access_token = request_headers.get("Authorization")

        if access_token is None:
            raise ConnectionRefusedError("No access token provided")
        
        # parse user openid
        token_parsed = parse_access_token(access_token)
        self.author_id = token_parsed.get('sub')

        # call system api
        mgmt_api_token = get_access_token()
        self.auth0 = Auth0(AUTH0_DOMAIN, mgmt_api_token)

        # init user_info
        self._get_user_infos()

    async def is_project_member(self):
        return True
    
    def _get_role(self):
        return [r.get('name') for r in self.auth0.users.list_roles(self.author_id).get('roles', {})]

    async def get_member_role(self):
        return self._get_role()

    async def get_user_infos(self) -> UserDict:
        return self._get_user_infos()
    
    def _get_user_infos(self) -> UserDict:
        res = self.auth0.users.get(self.author_id)
        self.user_infos = {
            "openId": self.author_id,
            "name": res.get('name'),
            "email": res.get('email'),
            "roles": self._get_role()
        }
        return self.user_infos

    async def get_project_members(self):
        return []


def base64_id_to_int(id_b64encode: str) -> int:
    if isinstance(id_b64encode, int):
        return id_b64encode
    return eval(base64.b64decode(id_b64encode).decode('utf-8'))[-1]

class CustomDBClient(BaseDBClient, GraphQLClient):
    conversation_id: Optional[str] = None
    user_infos: Optional[UserDict] = None
    # author_id: Optional[str] = None
    lock: asyncio.Lock

    def __init__(self, 
        handshake_headers: Optional[Dict[str, str]] = None,
        request_headers: Optional[Headers] = None,
        user_infos: Optional[UserDict] = None
    ):
        self.lock = asyncio.Lock()

        self.plugin_status_map = {
            0: "Offline", 1: "Coming soon", 2: "Suspended", 3: "Online"
        }

        self.user_infos = user_infos
        if not user_infos:
            auth_client = CustomAuthClient(handshake_headers, request_headers)
            self.user_infos = auth_client.get_user_infos()

        super().__init__()

    async def create_user(self, variables: UserDict) -> (bool, list):
        if not variables:
            return False, self.user_infos
        mutation = """
            mutation ($openId: String!, $name: String!, $email: String!, $roles: [String!]!) {
                insert_User_one(object: {openId: $openId, name: $name, email: $email, roles: $roles}, on_conflict: {constraint: User_openId_key, update_columns: [roles, name, email]}) {
                    id
                    Agents(where: {is_default: {_eq: true}}) {
                        name
                    }
                }
            }
            """
        res = await self.mutation(mutation, variables)
        if self.check_for_errors(res):
            logger.warning("Could not create user.")
            return False, self.user_infos
        self.user_infos['id'] = res.get('data', {}).get('insert_User_one', {}).get('id')
        agents = res.get('data', {}).get('insert_User_one', {}).get('Agents', [])
        self.user_infos['agent_name'] = agents[0].get('name') if agents else None
        return True, self.user_infos

    async def get_project_members(self):
        return []

    async def create_conversation(self) -> int|str:
        # If we run multiple send concurrently, we need to make sure we don't create multiple conversations.
        async with self.lock:
            if self.conversation_id:
                return self.conversation_id

            mutation = """
            mutation ($authorId: String) {
				insert_Conversation_one(object: {authorId: $authorId}) {
					id
				}
            }
            """
            variables = {"authorId": self.user_infos.get('openId')}
            res = await self.mutation(mutation, variables)

            if self.check_for_errors(res):
                logger.warning("Could not create conversation.")
                return None

            id_b64encode = res["data"]["insert_Conversation_one"]["id"]
            return base64_id_to_int(id_b64encode)

    async def get_conversation_id(self):
        self.conversation_id = await self.create_conversation()

        return base64_id_to_int(self.conversation_id)

    async def delete_conversation(self, conversation_id: int):
        mutation = """mutation ($id: Int!) {
			delete_Conversation_by_pk(id: $id) {
				id
			}
		}"""
        variables = {"id": conversation_id}
        res = await self.mutation(mutation, variables)
        self.check_for_errors(res, raise_error=True)

        return True

    async def get_conversation(self, conversation_id: int):
        query = """query ($id: Int!) {
			Conversation_connection(where: {id: {_eq: $id}}) {
				edges {
					node {
						createdAt
						id
						Messages(order_by: {createdAt: asc}) {
							id
							isError
							parentId
							indent
							author
							content
							waitForAnswer
							humanFeedback
							language
							prompt
							llmSettings
							authorIsUser
							createdAt
						}
						Elements {
							id
							conversationId
							type
							name
							url
							display
							language
							size
							forIds
						}
					}
				}
			}
		}"""
        variables = {
            "id": conversation_id,
        }
        res = await self.query(query, variables)
        self.check_for_errors(res, raise_error=True)

        node = res["data"]["Conversation_connection"]['edges'][0]['node']
        for m in node['Messages']:
            m['id'] = base64_id_to_int(m['id'])
        for e in node['Elements']:
            e['id'] = base64_id_to_int(e['id'])
        conversation = {
            "id": base64_id_to_int(node['id']),
            "createdAt": node['createdAt'],
            'messages': node['Messages'],
            'elements': node['Elements']
        }
        return conversation

    async def get_conversations(self, pagination, filter):
        if filter.search:
            query_name = "search_messages_connection"
            query = """query (
                $first: Int
                $cursor: String
                $withFeedback: [Int]=[-1, 0, 1]
                $search: String
                $authorId: String
            ) {
                  search_messages_connection(args: {search: $search}, after: $cursor, first: $first, where: {authorIsUser: {_eq: true}, Conversation: {authorId: {_eq: $authorId}, Messages: {humanFeedback: {_in: $withFeedback}}}}, order_by: {createdAt: desc}) {
                    edges {
                        cursor
                        node {
                            content
                            Conversation {
                                id
                            }
                            createdAt
                        }
                    }
                    pageInfo {
                        endCursor
                        hasNextPage
                    }
                }
            }"""

            variables = {
                "first": pagination.first,
                "cursor": pagination.cursor,
                "withFeedback": [filter.feedback] if filter.feedback else [-1, 0, 1],
                "authorId": self.user_infos.get('openId'),
                "search": filter.search,
            }
        else:
            query_name = "Message_connection"
            query = """query (
                $first: Int
                $cursor: String
                $withFeedback: [Int]=[-1, 0, 1]
                $authorId: String
            ) {
                Message_connection(after: $cursor, first: $first, where: {authorIsUser: {_eq: true}, Conversation: {authorId: {_eq: $authorId}, Messages: {humanFeedback: {_in: $withFeedback}}}}, order_by: {createdAt: desc}) {
                    edges {
                        cursor
                        node {
                            content
                            Conversation {
                                id
                            }
                            createdAt
                        }
                    }
                    pageInfo {
                        endCursor
                        hasNextPage
                    }
                }
            }"""
            variables = {
                "first": pagination.first,
                "cursor": pagination.cursor,
                "withFeedback": [filter.feedback] if filter.feedback else [-1, 0, 1],
                "authorId": self.user_infos.get('openId'),
            }
        res = await self.query(query, variables)
        self.check_for_errors(res, raise_error=True)

        conversations = []

        for edge in res["data"][query_name]["edges"]:
            node = edge["node"]
            node = {
                "id": base64_id_to_int(node['Conversation']['id']),
                "createdAt": node['createdAt'],
                # "elementCount": conversation['Conversation']['Elements_aggregate']['aggregate']['count'],
                # 'messageCount': conversation['Conversation']['Messages_aggregate']['aggregate']['count'],
                "messages": [{"content": node['content']}],
            }
            # node to cloud
            conversations.append(node)

        page_info = res["data"][query_name]["pageInfo"]
        
        return PaginatedResponse(
            pageInfo=PageInfo(
                hasNextPage=page_info["hasNextPage"],
                endCursor=page_info["endCursor"],
            ),
            data=conversations,
        )

    async def set_human_feedback(self, message_id, feedback):
        mutation = """mutation ($messageId: Int!, $humanFeedback: Int!) {
                        update_Message_by_pk(pk_columns: {id: $messageId}, _set: {humanFeedback: $humanFeedback}) {
                            id
                            humanFeedback
                    }
                }"""
        variables = {"messageId": message_id, "humanFeedback": feedback}
        res = await self.mutation(mutation, variables)
        self.check_for_errors(res, raise_error=True)

        return True

    async def get_message(self):
        raise NotImplementedError

    async def create_message(self, variables: MessageDict) -> int:
        c_id = await self.get_conversation_id()

        if not c_id:
            logger.warning("Missing conversation ID, could not persist the message.")
            return None

        variables["conversationId"] = c_id

        mutation = """
        mutation ($conversationId: Int!, $author: String!, $content: String!, $language: String, $prompt: String, $llmSettings: jsonb, $isError: Boolean=false, $parentId: Int=-1, $indent: Int=0, $authorIsUser: Boolean=false, $waitForAnswer: Boolean=false) {
            insert_Message_one(object: {author: $author, authorIsUser: $authorIsUser, content: $content, conversationId: $conversationId, indent: $indent, parentId: $parentId, isError: $isError, language: $language, llmSettings: $llmSettings, prompt: $prompt, waitForAnswer: $waitForAnswer}) {
                id
            }
        }
        """
        
        res = await self.mutation(mutation, variables)
        if self.check_for_errors(res):
            logger.warning("Could not create message.")
            return None

        id_b64encode = res["data"]["insert_Message_one"]["id"]
        return base64_id_to_int(id_b64encode)
        

    async def update_message(self, message_id: int, variables: MessageDict) -> bool:
        mutation = """
        mutation ($messageId: Int!, $author: String!, $content: String!, $language: String, $prompt: String, $parentId: Int, $llmSettings: jsonb) {
            update_Message_by_pk(pk_columns: {id: $messageId}, _set: {author: $author, content: $content, parentId: $parentId, language: $language, llmSettings: $llmSettings, prompt: $prompt}) {
                id
            }
        }
        """
        variables["messageId"] = message_id
        res = await self.mutation(mutation, variables)

        if self.check_for_errors(res):
            logger.warning("Could not update message.")
            return False

        return True

    async def delete_message(self, message_id: int) -> bool:
        mutation = """
        mutation ($messageId: Int!) {
            delete_Message_by_pk(id: $messageId) {
                id
            }
        }
        """
        res = await self.mutation(mutation, {"messageId": message_id})

        if self.check_for_errors(res):
            logger.warning("Could not delete message.")
            return False

        return True

    async def get_element(self, conversation_id, element_id):
        query = """query (
			$conversationId: Int!
			$id: Int!
		) {
			  Element_connection(where: {conversationId: {_eq: $conversationId}, id: {_eq: $id}}) {
				edges {
					node {
						id
						conversationId
						type
						name
						url
						display
						language
						size
						forIds
					}
				}
			}
    	}"""

        variables = {
            "conversationId": conversation_id,
            "id": element_id,
        }
        res = await self.query(query, variables)
        self.check_for_errors(res, raise_error=True)

        return res["data"]["Element_connection"]['edges']['node']

    async def create_element(self, variables):
        c_id = await self.get_conversation_id()

        if not c_id:
            logger.warning("Missing conversation ID, could not persist the element.")
            return None

        mutation_name = "insert_Element_one"
        mutation = """
        mutation ($conversationId: Int!, $type: String!, $url: String!, $name: String!, $display: String!, $forIds: [String!]!, $size: String, $language: String) {
            insert_Element_one(object: {conversationId: $conversationId, display: $display, forIds: $forIds, language: $language, name: $name, size: $size, type: $type, url: $url}) {
                id,
                type,
                url,
                name,
                display,
                size,
                language,
                forIds
            }
        }
        """
        variables["conversationId"] = c_id
        res = await self.mutation(mutation, variables)

        if self.check_for_errors(res):
            logger.warning("Could not persist element.")
            return None

        return res["data"][mutation_name]
    
    async def update_element(self, variables):
        c_id = await self.get_conversation_id()

        if not c_id:
            logger.warning("Missing conversation ID, could not persist the element.")
            return None

        mutation_name = "update_Element_by_pk"
        mutation = """
        mutation ($conversationId: Int!, $id: Int!, $forIds: [String!]!) {
            update_Element_by_pk(pk_columns: {id: $id}, _set: {conversationId: $conversationId, forIds: $forIds}) {
                id,
            }
        }
        """
        variables["conversationId"] = c_id
        variables['id'] = base64_id_to_int(variables['id'])
        res = await self.mutation(mutation, variables)

        if self.check_for_errors(res):
            logger.warning("Could not persist element.")
            return None

        return res["data"][mutation_name]

    async def upload_element(self, content: bytes, mime: str, type: str=None, ext: str=None) -> str:
        s3_client = S3Client(config.s3.bucket)
        id = f"{uuid.uuid4()}"
        object_name = f"{type}s/{id}.{ext}"
        s3_client.upload_fileobj(content, object_name)
        return f"{config.s3.domain}{object_name}"

    async def get_examples(self, pagination):
        query = """
            query ($first: Int, $cursor: String) {
                Example_connection(order_by: {createdAt: desc}, after: $cursor, first: $first) {
                    edges {
                        node {
                            name
                            prompt
                            status
                            tags
                        }
                        cursor
                    }
                    pageInfo {
                        endCursor
                        hasNextPage
                    }
                }
            }
        """
        variables = {
            "first": pagination.first,
            "cursor": pagination.cursor
        }
        res = await self.query(query, variables)
        self.check_for_errors(res, raise_error=True)

        examples = []

        for edge in res["data"]["Example_connection"]["edges"]:
            examples.append(edge["node"])

        page_info = res["data"]["Example_connection"]["pageInfo"]

        return PaginatedResponse(
            pageInfo=PageInfo(
                hasNextPage=page_info["hasNextPage"],
                endCursor=page_info["endCursor"],
            ),
            data=examples,
        )

    async def get_plugins(self, pagination, filter):
        variables = {
                "first": pagination.first,
                "after": pagination.cursor,
        }
        if filter.search:
            query_name = "search_plugins_connection"
            query_prefix_search_cate_tag = """
            query MyQuery($first: Int! = 20, $after: String, $search: String!, $categories: [String!], $tags: [String!]{user_id_placeholder}) {
                search_plugins_connection(first: $first, where: {status: {_gt: 0}, category: {_in: $categories}, tags: {_contains: $tags}}, order_by: {avgServiceLevelFromRapid: desc, popularityScore: desc, avgLatencyFromRapid: asc}, args: {search: $search}, after: $after) {
                    """
            query_prefix_search_cate = """
            query MyQuery($first: Int! = 20, $after: String, $search: String!, $categories: [String!]{user_id_placeholder}) {
                search_plugins_connection(first: $first, where: {status: {_gt: 0}, category: {_in: $categories}}, order_by: {avgServiceLevelFromRapid: desc, popularityScore: desc, avgLatencyFromRapid: asc}, args: {search: $search}, after: $after) {
                    """
            query_prefix_search_tag = """
            query MyQuery($first: Int! = 20, $after: String, $search: String!, $tags: [String!]{user_id_placeholder}) {
                search_plugins_connection(first: $first, where: {status: {_gt: 0}, tags: {_contains: $tags}}, order_by: {avgServiceLevelFromRapid: desc, popularityScore: desc, avgLatencyFromRapid: asc}, args: {search: $search}, after: $after) {
                    """
            query_prefix_search = """
            query MyQuery($first: Int! = 20, $after: String, $search: String!{user_id_placeholder}) {
                search_plugins_connection(first: $first, where: {status: {_gt: 0}}, order_by: {avgServiceLevelFromRapid: desc, popularityScore: desc, avgLatencyFromRapid: asc}, args: {search: $search}, after: $after) {
                    """
            variables['search'] = filter.search
        else:
            query_name = "Plugin_connection"
            query_prefix_search_cate_tag = """
            query MyQuery($first: Int! = 20, $after: String, $categories: [String!], $tags: [String!]{user_id_placeholder}) {
                Plugin_connection(first: $first, where: {status: {_gt: 0}, category: {_in: $categories}, tags: {_contains: $tags}}, order_by: {avgServiceLevelFromRapid: desc, popularityScore: desc, avgLatencyFromRapid: asc}, after: $after) {
                    """
            query_prefix_search_cate = """
            query MyQuery($first: Int! = 20, $after: String, $categories: [String!]{user_id_placeholder}) {
                Plugin_connection(first: $first, where: {status: {_gt: 0}, category: {_in: $categories}}, order_by: {avgServiceLevelFromRapid: desc, popularityScore: desc, avgLatencyFromRapid: asc}, after: $after) {
                    """
            query_prefix_search_tag = """
            query MyQuery($first: Int! = 20, $after: String, $tags: [String!]{user_id_placeholder}) {
                Plugin_connection(first: $first, where: {status: {_gt: 0}, tags: {_contains: $tags}}, order_by: {avgServiceLevelFromRapid: desc, popularityScore: desc, avgLatencyFromRapid: asc}, after: $after) {
                    """
            query_prefix_search = """
            query MyQuery($first: Int! = 20, $after: String{user_id_placeholder}) {
                Plugin_connection(first: $first, where: {status: {_gt: 0}}, order_by: {avgServiceLevelFromRapid: desc, popularityScore: desc, avgLatencyFromRapid: asc}, after: $after) {
                    """

        query_suffix = """
                pageInfo {
                        endCursor
                        hasNextPage
                }
                edges {
                    node {
                        id
                        description_for_human
                        name_for_human
                        popularityScore
                        thumbnail
                        avgServiceLevelFromRapid
                        avgLatencyFromRapid
                        promptExamples
                        status
                        {subscription_placeholder}
                    }
                }
            }
        }"""

        if filter.categories and filter.tags:
            query = query_prefix_search_cate_tag + query_suffix
            variables['categories'] = filter.categories
            variables['tags'] = filter.tags
        elif filter.categories:
            query = query_prefix_search_cate + query_suffix
            variables['categories'] = filter.categories
        elif filter.tags:
            query = query_prefix_search_tag + query_suffix
            variables['tags'] = filter.tags
        else:
            query = query_prefix_search + query_suffix

        # 存在用户id 时，判断用户是否订阅了该插件
        if self.user_infos.get('id'):
            query = query.replace('{user_id_placeholder}', f", $userId: Int!").replace('{subscription_placeholder}', """Subscriptions(where: {userId: {_eq: $userId}, status: {_eq: true}}) {
                            userId
                            status
                        }""")
        else:
            query = query.replace('{user_id_placeholder}', "").replace('{subscription_placeholder}', "")

        res = await self.query(query, variables)
        self.check_for_errors(res, raise_error=True)

        plugins = []

        for edge in res["data"][query_name]["edges"]:
            node = edge["node"]
            node["id"] = base64_id_to_int(node['id'])
            node["is_subscribed"] = len(node.get('Subscriptions', [])) > 0
            del node['Subscriptions']
            node['status'] = self.plugin_status_map.get(node.get('status'), 1)
            plugins.append(node)

        page_info = res["data"][query_name]["pageInfo"]
        
        return PaginatedResponse(
            pageInfo=PageInfo(
                hasNextPage=page_info["hasNextPage"],
                endCursor=page_info["endCursor"],
            ),
            data=plugins,
        )
    
    async def get_plugin_categories(self):
        query = """
            query MyQuery {
                Plugin_connection(distinct_on: category) {
                    edges {
                        node {
                            category
                        }
                    }
                }
            }
        """

        res = await self.query(query)
        return [t.get('node', {}).get('category') for t in res.get('data', {}).get('Plugin_connection', {}).get('edges', [])]

    async def subscribe(self, pluginId: int):
        mutation = """
            mutation MyMutation($userId: Int!, $pluginId: Int!) {
                insert_Subscription_one(object: {pluginId: $pluginId, userId: $userId}, on_conflict: {constraint: Subscription_userId_pluginId_key, update_columns: [status]}) {
                    id
                }
            }
        """
        vars = {
            "userId": self.user_infos.get('id'),
            "pluginId": pluginId
        }

        res = self.mutation(mutation, vars)
        if self.check_for_errors(res):
            logger.warning(f"Could not subscribe plugin {pluginId}.")
            return False
        
        return True

    async def unsubscribe(self, pluginId: int):
        mutation = """
        mutation MyMutation($userId: Int!, $pluginId: Int!) {
            update_Subscription(where: {pluginId: {_eq: $pluginId}, userId: {_eq: $userId}}, _set: {status: false}) {
                returning {
                    status
                }
            }
        }
        """
        vars = {
            "userId": self.user_infos.get('id'),
            "pluginId": pluginId
        }

        res = self.mutation(mutation, vars)
        if self.check_for_errors(res):
            logger.warning(f"Could not subscribe plugin {pluginId}.")
            return False
        
        return True