from typing import Dict, Any, Optional
import uuid
import os
import asyncio
import aiohttp
from python_graphql_client import GraphqlClient

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
    def __init__(self, access_token: str):
        # self.headers = {
        #     "Authorization": access_token,
        #     "content-type": "application/json",
        # }
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

    def __init__(self, access_token: str):
        if access_token:
            # parse user openid
            token_parsed = parse_access_token(access_token)
            self.author_id = token_parsed.get('sub')

        # call system api
        mgmt_api_token = get_access_token()
        self.auth0 = Auth0(AUTH0_DOMAIN, mgmt_api_token)

    async def is_project_member(self):
        return True

    async def get_member_role(self):
        return self.auth0.users.list_roles(self.author_id).get('roles', {})

    async def get_project_members(self):
        return []


def base64_id_to_int(id_b64encode: str) -> int:
    return eval(base64.b64decode(id_b64encode).decode('utf-8'))[-1]

class CustomDBClient(BaseDBClient, GraphQLClient):
    conversation_id: Optional[str] = None
    author_id: Optional[str] = None
    lock: asyncio.Lock

    def __init__(self, access_token: str):
        self.lock = asyncio.Lock()
        # 解码access_token 获取用户openid
        if access_token:
            token_parsed = parse_access_token(access_token)
            self.author_id = token_parsed.get('sub')
        super().__init__(access_token)

    async def create_conversation(self, sessionId: str=None) -> int|str:
        # If we run multiple send concurrently, we need to make sure we don't create multiple conversations.
        async with self.lock:
            if self.conversation_id:
                return self.conversation_id

            mutation = """
            mutation ($sessionId: String, $authorId: String) {
				insert_Conversation_one(object: {sessionId: $sessionId, authorId: $authorId}) {
					id
				}
            }
            """
            variables = {"sessionId": sessionId, "authorId": self.author_id}
            res = await self.mutation(mutation, variables)

            if self.check_for_errors(res):
                logger.warning("Could not create conversation.")
                return None

            id_b64encode = res["data"]["insert_Conversation_one"]["id"]
            return base64_id_to_int(id_b64encode)

    async def get_conversation_id(self, sessionId: str=None):
        self.conversation_id = await self.create_conversation(sessionId)

        return self.conversation_id

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
						Messages {
							id
							isError
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
                search_messages_connection(args: {search: $search}, where: {humanFeedback: {_in: $withFeedback}, authorIsUser: {_eq: true}, Conversation: {authorId: {_eq: $authorId}}}, first: $first, after: $cursor) {
                    edges {
                        node {
                            Conversation {
                                id
                                createdAt
                                Elements_aggregate {
                                    aggregate {
                                        count(distinct: true)
                                    }
                                }
                                Messages_aggregate {
                                    aggregate {
                                        count(distinct: true)
                                    }
                                }
                                Messages {
                                    content
                                }
                            }
                        }
                        cursor
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
                "withFeedback": filter.feedback if filter.feedback else [-1, 0, 1],
                "authorId": self.author_id,
                "search": filter.search,
            }
        else:
            query_name = "Conversation_connection"
            query = """query (
                $first: Int
                $cursor: String
                $withFeedback: [Int]=[-1, 0, 1]
                $authorId: String
            ) {
                Conversation_connection(first: $first, after: $cursor, where: {authorId: {_eq: $authorId}, Messages: {humanFeedback: {_in: $withFeedback}}}) {
                    edges {
                        node {
                            id
                            createdAt
                            Elements_aggregate {
                                aggregate {
                                    count(distinct: true)
                                }
                            }
                            Messages_aggregate {
                                aggregate {
                                    count(distinct: true)
                                }
                            }
                            Messages {
                                content
                            }
                        }
                        cursor
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
                "withFeedback": filter.feedback if filter.feedback else [-1, 0, 1],
                "authorId": self.author_id,
            }
        res = await self.query(query, variables)
        self.check_for_errors(res, raise_error=True)

        conversations = []

        for edge in res["data"][query_name]["edges"]:
            conversation = edge["node"]['Conversation'] if query_name != "Conversation_connection" else edge["node"]
            node = {
                "id": base64_id_to_int(conversation['id']),
                "createdAt": conversation['createdAt'],
                "elementCount": conversation['Elements_aggregate']['aggregate']['count'],
                'messageCount': conversation['Messages_aggregate']['aggregate']['count'],
                "messages": conversation['Messages'],
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

    async def create_message(self, variables: Dict[str, Any]) -> int:
        c_id = await self.get_conversation_id(variables.get('sessionId'))

        if not c_id:
            logger.warning("Missing conversation ID, could not persist the message.")
            return None

        variables["conversationId"] = c_id

        mutation = """
        mutation ($conversationId: Int!, $author: String!, $content: String!, $language: String, $prompt: String, $llmSettings: jsonb, $isError: Boolean=false, $indent: Int=0, $authorIsUser: Boolean=false, $waitForAnswer: Boolean=false) {
            insert_Message_one(object: {author: $author, authorIsUser: $authorIsUser, content: $content, conversationId: $conversationId, indent: $indent, isError: $isError, language: $language, llmSettings: $llmSettings, prompt: $prompt, waitForAnswer: $waitForAnswer}) {
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
        

    async def update_message(self, message_id: int, variables: Dict[str, Any]) -> bool:
        mutation = """
        mutation ($messageId: Int!, $author: String!, $content: String!, $language: String, $prompt: String, $llmSettings: jsonb) {
            update_Message_by_pk(pk_columns: {id: $messageId}, _set: {author: $author, content: $content, language: $language, llmSettings: $llmSettings, prompt: $prompt}) {
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

    async def upsert_element(self, variables):
        c_id = await self.get_conversation_id()

        if not c_id:
            logger.warning("Missing conversation ID, could not persist the element.")
            return None

        if "id" in variables:
            mutation_name = "update_Element_by_pk"
            mutation = """
            mutation ($conversationId: Int!, $id: Int!, $forIds: [String!]!) {
                update_Element_by_pk(pk_columns: {id: $id}, _set: {conversationId: $conversationId, forIds: $forIds}) {
                    id,
                }
            }
            """
            variables["conversationId"] = c_id
            res = await self.mutation(mutation, variables)
        else:
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

    async def upload_element(self, content: bytes, mime: str, type: str=None, ext: str=None) -> str:
        s3_client = S3Client(config.s3.bucket)
        id = f"{uuid.uuid4()}"
        object_name = f"{type}s/{id}.{ext}"
        s3_client.upload_fileobj(content, object_name)
        return f"{config.s3.domain}{object_name}"


