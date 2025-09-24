# Logic for detecting hidden data

from PIL import Image
import logging

def chi_square_lsb(image_path: str) -> float:
    """Return a simple chi-square score based on LSB distribution.
    Lower scores typically mean more uniform LSBs (potentially more embedding),
    but this is only a heuristic.
    """
    logging.debug(f'Running chi-square LSB analysis on {image_path}')
    with Image.open(image_path) as img:
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        pixels = list(img.getdata())

    # Collect LSBs from R,G,B
    zeros = 0
    ones = 0
    for p in pixels:
        r, g, b = p[:3]
        zeros += 1 if (r & 1) == 0 else 0
        ones += 1 if (r & 1) == 1 else 0
        zeros += 1 if (g & 1) == 0 else 0
        ones += 1 if (g & 1) == 1 else 0
        zeros += 1 if (b & 1) == 0 else 0
        ones += 1 if (b & 1) == 1 else 0

    total = zeros + ones
    if total == 0:
        return 0.0
    expected = total / 2.0
    # Chi-square for two categories: sum((obs-exp)^2/exp)
    chi2 = ((zeros - expected) ** 2) / expected + ((ones - expected) ** 2) / expected
    logging.debug(f'Chi-square LSB result for {image_path}: {float(chi2)}')
    return float(chi2)
