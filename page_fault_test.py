
import time

import numpy as np

# Allocate and access large arrays to trigger page faults
for i in range(20):
    # Allocate large array
    arr = np.zeros((1000, 1000, 10))
    # Touch all pages
    arr[:] = i
    # Force some computation
    result = np.sum(arr)
    time.sleep(0.1)
    print(f"Iteration {i}, sum: {result}")
