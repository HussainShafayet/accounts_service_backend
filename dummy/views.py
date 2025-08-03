from rest_framework.views import APIView;
from rest_framework.response import Response;
from rest_framework import status;
from .serializers import SumSerializer;
from .models import CalculationCounter;


class SumApiView(APIView):
    """
    API view to calculate the sum of two integers.
    """
    def post(self, request):
        serializer = SumSerializer(data=request.data);
        if serializer.is_valid():
            a = serializer.validated_data['a'];
            b = serializer.validated_data['b'];
            result = a + b;
            
            counter, created = CalculationCounter.objects.get_or_create(id=1);
            counter.count += 1;
            counter.save();
            
            return Response({'result': result, 'count': counter.count}, status=status.HTTP_200_OK);
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST);
        