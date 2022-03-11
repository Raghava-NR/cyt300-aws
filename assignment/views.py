from django.shortcuts import render
from rest_framework import permissions
from .serializers import SubmissionSerializer
from .models import Submission
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import generics, mixins, viewsets, status
import boto3
from django.conf import settings
import base64


# Create your views here.
from django.http import HttpResponse


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
    def encrypt_data(self, request):

        plain_text = request.data.get("text", "")

        client = self.aws_kms_client()

        encrypted_result = client.encrypt(KeyId=settings.AWS_KMS_KEY_ID, Plaintext=plain_text)

        return Response({"Success": True, "encrypted_text": base64.b64encode(
            encrypted_result["CiphertextBlob"]
        )},
                        status=status.HTTP_200_OK)

    @action(detail=False, methods=["POST"])
    def decrypt_data(self, request):

        encrypted_text = request.data.get("encrypted_text", "")

        client = self.aws_kms_client()

        decrypted_result = client.decrypt(CiphertextBlob=base64.b64decode(encrypted_text))


        return Response({"Success": True, "text": decrypted_result["Plaintext"]},
                        status=status.HTTP_200_OK)







