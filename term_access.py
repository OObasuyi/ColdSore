from argparse import ArgumentParser
from coldSore import Sore


def term_access():
    parser = ArgumentParser(prog='coldSore.py', description='ColdFarm')
    cold_args = parser.add_argument_group(title='ColdSore Fields')
    cold_args.add_argument('--config_file', help='location of config file', default='config.yaml', type=str)
    args = parser.parse_args()

    agg_data_to_ise = Sore(config=args.config_file)
    agg_data_to_ise.push_to_ise()


if __name__ == '__main__':
    term_access()
