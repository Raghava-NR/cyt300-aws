from django.shortcuts import render
from rest_framework import permissions
from .serializers import SubmissionSerializer
from .models import Submission
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import generics, mixins, viewsets, status
import boto3
from cryptography.fernet import Fernet
from django.conf import settings
import base64
import logging
from django.http import HttpResponse
from botocore.exceptions import ClientError
import uuid
from django.http import FileResponse



NUM_BYTES_FOR_LEN = 4
TEMP_FILE_NAME = 'temp_file.pdf'
CONTENT_TYPE_ALLOWED = 'application/pdf'


def index(request):
    return HttpResponse("Hello. This is CYT300 Project for Group 3.")



class SubmissionViewSet(viewsets.ModelViewSet):

    """
    API endpoint that allows Submissions to be viewed or edited.
    """

    queryset = Submission.objects.all().order_by('-created_at')
    serializer_class = SubmissionSerializer
    permission_classes = []


    @staticmethod
    def aws_kms_client():

        client = boto3.client('kms', region_name=settings.AWS_REGION)

        return client

    @action(detail=False, methods=["POST"])
    def encrypt_text(self, request):

        """

        :param request:
        :return: API Response, encrypted text
        """

        plain_text = request.data.get("text", "")

        client = self.aws_kms_client()

        encrypted_result = client.encrypt(KeyId=settings.AWS_KMS_KEY_ID, Plaintext=plain_text)

        return Response({"Success": True, "encrypted_text": base64.b64encode(
            encrypted_result["CiphertextBlob"]
        )},
                        status=status.HTTP_200_OK)

    @action(detail=False, methods=["POST"])
    def decrypt_text(self, request):

        """

        :param request:
        :return: API Response, decrypted text (plain-text)
        """

        encrypted_text = request.data.get("encrypted_text", "")

        client = self.aws_kms_client()

        decrypted_result = client.decrypt(CiphertextBlob=base64.b64decode(encrypted_text))


        return Response({"Success": True, "text": decrypted_result["Plaintext"]},
                        status=status.HTTP_200_OK)

    @classmethod
    def create_data_key(cls, cmk_id, key_spec='AES_256'):
        """Generate a data key to use when encrypting and decrypting data

        :param cmk_id: KMS CMK ID or ARN under which to generate and encrypt the
        data key.
        :param key_spec: Length of the data encryption key. Supported values:
            'AES_128': Generate a 128-bit symmetric key
            'AES_256': Generate a 256-bit symmetric key
        :return Tuple(EncryptedDataKey, PlaintextDataKey) where:
            EncryptedDataKey: Encrypted CiphertextBlob data key as binary string
            PlaintextDataKey: Plaintext base64-encoded data key as binary string
        :return Tuple(None, None) if error
        """

        # Create data key
        kms_client = cls.aws_kms_client()
        try:
            response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)
        except ClientError as e:
            logging.error(e)
            return None, None

        # Return the encrypted and plaintext data key
        return response['CiphertextBlob'], base64.b64encode(response['Plaintext'])


    @classmethod
    def decrypt_data_key(cls, data_key_encrypted):

        """Decrypt an encrypted data key

        :param data_key_encrypted: Encrypted ciphertext data key.
        :return Plaintext base64-encoded binary data key as binary string
        :return None if error
        """

        # Decrypt the data key
        kms_client = cls.aws_kms_client()

        response = kms_client.decrypt(CiphertextBlob=data_key_encrypted)

        # Return plaintext base64-encoded binary data key
        return base64.b64encode((response['Plaintext']))


    def encrypt_file(self, filename, cmk_id=settings.AWS_KMS_KEY_ID):

        """Encrypt a file using an AWS KMS CMK

        A data key is generated and associated with the CMK.
        The encrypted data key is saved with the encrypted file. This enables the
        file to be decrypted at any time in the future and by any program that
        has the credentials to decrypt the data key.
        The encrypted file is saved to <filename>.encrypted
        Limitation: The contents of filename must fit in memory.

        :param filename: File to encrypt
        :param cmk_id: AWS KMS CMK ID or ARN
        :return: True if file was encrypted. Otherwise, False.
        """

        # Read the entire file into memory
        try:
            with open(filename, 'rb') as file:
                file_contents = file.read()
        except IOError as e:
            logging.error(e)
            return False

        # Generate a data key associated with the CMK
        # The data key is used to encrypt the file. Each file can use its own
        # data key or data keys can be shared among files.
        # Specify either the CMK ID or ARN
        data_key_encrypted, data_key_plaintext = self.create_data_key(cmk_id)
        if data_key_encrypted is None:
            return False
        logging.info('Created new AWS KMS data key')

        # Encrypt the file
        f = Fernet(data_key_plaintext)
        file_contents_encrypted = f.encrypt(file_contents)

        # Write the encrypted data key and encrypted file contents together
        try:
            with open(filename + '.encrypted', 'wb') as file_encrypted:
                file_encrypted.write(len(data_key_encrypted).to_bytes(NUM_BYTES_FOR_LEN,
                                                                      byteorder='big'))
                file_encrypted.write(data_key_encrypted)
                file_encrypted.write(file_contents_encrypted)
        except IOError as e:
            logging.error(e)
            return False

        # For the highest security, the data_key_plaintext value should be wiped
        # from memory. Unfortunately, this is not possible in Python. However,
        # storing the value in a local variable makes it available for garbage
        # collection.
        return True

    def decrypt_file(self, filename):
        """Decrypt a file encrypted by encrypt_file()

        The encrypted file is read from <filename>
        The decrypted file is written to <filename>.decrypted

        :param filename: File to decrypt
        :return: True if file was decrypted. Otherwise, False.
        """

        # Read the encrypted file into memory
        try:
            with open(filename, 'rb') as file:
                file_contents = file.read()
        except IOError as e:
            logging.error(e)
            return False

        # The first NUM_BYTES_FOR_LEN bytes contain the integer length of the
        # encrypted data key.
        # Add NUM_BYTES_FOR_LEN to get index of end of encrypted data key/start
        # of encrypted data.
        data_key_encrypted_len = int.from_bytes(file_contents[:NUM_BYTES_FOR_LEN],
                                                byteorder='big') \
                                 + NUM_BYTES_FOR_LEN
        data_key_encrypted = file_contents[NUM_BYTES_FOR_LEN:data_key_encrypted_len]

        # Decrypt the data key before using it
        data_key_plaintext = self.decrypt_data_key(data_key_encrypted)
        if data_key_plaintext is None:
            return False

        # Decrypt the rest of the file
        f = Fernet(data_key_plaintext)
        file_contents_decrypted = f.decrypt(file_contents[data_key_encrypted_len:])

        # Write the decrypted file contents
        try:
            with open(filename + '.decrypted', 'wb') as file_decrypted:
                file_decrypted.write(file_contents_decrypted)
        except IOError as e:
            logging.error(e)
            return False

        # The same security issue described at the end of encrypt_file() exists
        # here, too, i.e., the wish to wipe the data_key_plaintext value from
        # memory.
        return True


    @staticmethod
    def upload_file_to_s3(file_name, s3_path):

        s3 = boto3.resource('s3')

        s3.Bucket(settings.AWS_S3_BUCKET_NAME).upload_file(file_name, s3_path)


    @action(detail=False, methods=["POST"])
    def encrypt_file_api(self, request):


        file = request.FILES['file']

        if file.content_type != CONTENT_TYPE_ALLOWED:
            return Response({"Success": False, "message": "Only PDF is allowed"},
                        status=status.HTTP_200_OK)


        with open(TEMP_FILE_NAME, 'wb') as temp:

            temp.write(request.FILES['file'].file.getbuffer())

        file_encryption_status = self.encrypt_file(TEMP_FILE_NAME)

        if not file_encryption_status:

            return Response({"Success": False, "message": "Couldn't encrypt given file"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        s3_path = str(uuid.uuid4()) + '.pdf'

        self.upload_file_to_s3(TEMP_FILE_NAME+'.encrypted', s3_path)

        return Response({"Success": True, "message": "PDF encrypted and uploaded to S3.",
                         "s3_file_path": s3_path},
                        status=status.HTTP_200_OK)


    def download_s3_file_to_temp(self, s3_path):

        s3 = boto3.resource('s3')

        s3.Bucket(settings.AWS_S3_BUCKET_NAME).download_file(s3_path, TEMP_FILE_NAME)




    @action(detail=False, methods=["POST"])
    def decrypt_file_api(self, request):

        s3_file_path = request.data["s3_file_path"]

        # download file

        try:

            self.download_s3_file_to_temp(s3_file_path)

        except ClientError as e:

            if e.response['Error']['Code'] == "404":
                print("The object does not exist.")
                return Response({"Success": False, "message": "File not found in S3"},
                        status=status.HTTP_404_NOT_FOUND)

            else:
                return Response(
                    {"Success": False, "message": "Couldn't decrypt given file"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        file_decryption_status = self.decrypt_file(TEMP_FILE_NAME)

        if not file_decryption_status:
            return Response(
                {"Success": False, "message": "Couldn't decrypt given file"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        temp_file = open(TEMP_FILE_NAME + '.decrypted', 'rb')

        response = FileResponse(temp_file)

        return response
















