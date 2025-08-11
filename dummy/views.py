from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import connection, DatabaseError
from .serializers import SumSerializer

class SumApiView(APIView):
    """
    API view to calculate the sum of two integers without using ORM.
    It tracks how many times the sum API is called using raw SQL.
    """

    def _get_and_increment_count(self):
        with connection.cursor() as cursor:
            # Fetch current count for id=1
            cursor.execute("SELECT count FROM calculation_counter WHERE id = 1;")
            row = cursor.fetchone()

            if row is None:
                # Insert initial row with count 1 if missing
                cursor.execute("INSERT INTO calculation_counter (id, count) VALUES (1, 1);")
                return 1
            else:
                current_count = row[0] + 1
                # Update count
                cursor.execute("UPDATE calculation_counter SET count = %s WHERE id = 1;", [current_count])
                return current_count

    def post(self, request):
        serializer = SumSerializer(data=request.data)
        if serializer.is_valid():
            a = serializer.validated_data['a']
            b = serializer.validated_data['b']
            result = a + b

            try:
                count = self._get_and_increment_count()
            except DatabaseError as e:
                return Response({'error': 'Database error', 'details': str(e)},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'result': result, 'count': count}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
