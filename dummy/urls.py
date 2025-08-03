from django.urls import path
from .views import SumApiView

urlpatterns = [
    path('sum/', SumApiView.as_view()),
]
