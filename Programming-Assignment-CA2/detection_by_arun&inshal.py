from database import get_failed_attempts, get_last_ip, get_last_device
import datetime

def is_suspicious(u, ip, d):
    score = 0

    if get_failed_attempts(u) >= 3:
        score += 2

    last_ip = get_last_ip(u)
    if last_ip and last_ip != ip:
        score += 2

    last_device = get_last_device(u)
    if last_device and last_device != d:
        score += 2

    if datetime.datetime.now().hour < 6:
        score += 1

    return score >= 3
