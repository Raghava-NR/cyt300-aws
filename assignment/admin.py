from django.contrib import admin
from .models import *

# Register your models here.
from .models import Submission

admin.site.register(Submission)
