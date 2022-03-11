from django.urls import include,path
from rest_framework import routers

from . import views



router = routers.DefaultRouter()
router.register(r'submissions', views.SubmissionViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('index', views.index, name='index'),
]