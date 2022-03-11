from rest_framework import serializers
from .models import Submission



class SubmissionSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Submission
        fields = ['description', 'secrets',
                  'file_path', 'created_at',
                  'updated_at']