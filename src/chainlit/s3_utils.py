import os
import boto3
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class S3Client():
	def __init__(self, bucket=None) -> None:
		self.s3_client = boto3.client('s3')
		self.bucket = bucket
                
	def upload_file(self, file_name, bucket=None, object_name=None):
		"""Upload a file to an S3 bucket

		:param file_name: File to upload
		:param bucket: Bucket to upload to
		:param object_name: S3 object name. If not specified then file_name is used
		:return: True if file was uploaded, else False
		"""
		bucket = bucket or self.bucket
		# If S3 object_name was not specified, use file_name
		if object_name is None:
			object_name = os.path.basename(file_name)

		# Upload the file
		try:
			response = self.s3_client.upload_file(
				file_name, bucket, object_name, ExtraArgs={'ACL': 'public-read'})
		except ClientError as e:
			logger.error(e)
			return False
		return True
	
	def upload_fileobj(self, file_obj, object_name, bucket=None):
		bucket = bucket or self.bucket
		try:
			self.s3_client.upload_fileobj(
				file_obj, bucket, object_name, ExtraArgs={'ACL': 'public-read'})
		except ClientError as e:
			logger.error(e)
			return False
		return True
