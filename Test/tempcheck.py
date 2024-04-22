import pandas as pd
import random


def random_date_or_not(start, end):
    return random.choice([pd.to_datetime(random.randint(start.value, end.value), unit='ns').strftime('%Y-%m-%d'), 'never'])


def input_generator(amount: int = 25, start_date_offset: int = 3, seed: int = None):
    if seed and isinstance(seed, int):
        random.seed(seed)

    real_oui = ['E0:CB:1D', '40:92:1A', '4C:EC:0F', '98:40:BB']
    end_date = pd.Timestamp.now().normalize()
    start_date = end_date - pd.DateOffset(months=start_date_offset)

    data = []
    for _ in range(amount):
        mac_address = random.choice(real_oui).lower() + ':' + ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(3)])
        severityLow = random.randint(0, 10)
        severityMedium = random.randint(0, 10)
        severityHigh = random.randint(0, 10)
        severityCritical = random.randint(0, 10)
        lastAuthRunDate = str(random_date_or_not(start_date, end_date))
        lastUnauthRunDate = str(random_date_or_not(start_date, end_date))
        # make sure we get something
        while lastAuthRunDate == lastUnauthRunDate:
            lastAuthRunDate = random_date_or_not(start_date, end_date)

        rec_hold = {
            'mac': mac_address,
            'severityLow': severityLow,
            'severityMedium': severityMedium,
            'severityHigh': severityHigh,
            'severityCritical': severityCritical,
            'lastAuthRunDate': lastAuthRunDate,
            'lastUnauthRunDate': lastUnauthRunDate
        }
        data.append(rec_hold)

    return pd.DataFrame(data)


if __name__ == '__main__':
    test = input_generator()
    pass
