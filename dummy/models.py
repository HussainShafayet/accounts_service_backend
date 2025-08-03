from django.db import models

# Create your models here.
class CalculationCounter(models.Model):
    count = models.PositiveIntegerField(default=0);
    
    def __str__(self):
        return f"Sum called {self.count} times";