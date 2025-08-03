from rest_framework import serializers

class SumSerializer(serializers.Serializer):
    a = serializers.IntegerField();
    b = serializers.IntegerField();