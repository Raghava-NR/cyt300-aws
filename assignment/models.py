from django.db import models



class Submission(models.Model):


    description = models.CharField(max_length=256)

    secrets = models.TextField()

    file_path = models.CharField(max_length=512)

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

