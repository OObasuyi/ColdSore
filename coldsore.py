from json import loads, dumps

import pandas as pd
import requests
from requests import Session

from utils import log_collector, Rutils

requests.packages.urllib3.disable_warnings()


class Sore:
    UTILS = Rutils()

    def __init__(self, config: str = "config.yaml", verify_ssl=False):
        self.logger = log_collector(file_name='hazbag.log', func_name='ColdSore')
        # move config file to new folder
        config = self.UTILS.create_file_path('configs', config)
        self.config = self.UTILS.get_yaml_config(config, self)
        self.ssl_verify = verify_ssl
        self.ise_info = self.config['ISE']
        self.tenable_info = self.config['TENABLE']

    def ise_session(self):
        ise_session = Session()
        ise_session.verify = self.ssl_verify
        ise_session.headers = {"Accept": "application/xml", "Content-Type": "application/xml"}
        ise_session.auth = (self.ise_info['username'], self.ise_info['password'])
        return ise_session

    def pull_tenable_info(self):
        tenable_session = Session()
        tenable_session.verify = self.ssl_verify
        tenable_session.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "x-apikey":
                f"accesskey={self.tenable_info['accesskey']}; "
                f"secretkey={self.tenable_info['secretkey']}"}
        score_data_url = f'{self.tenable_info["node"]}/rest/analysis'
        sc_pd = pd.DataFrame([])  # holder

        req_score_data = {
            "type": "vuln",
            "query": {"id": self.tenable_info['query_id']},
            "sourceType": "cumulative"
        }
        # pull data from SC
        data_req = tenable_session.post(score_data_url, data=dumps(req_score_data))
        if data_req.status_code != 200:
            self.logger.critical(f'tenable: could not reach node at {score_data_url}')
            self.logger.critical(f'tenable: code recvd from node {data_req.status_code} \n\n CONTENT:\n\n\ {data_req.content}\n\n')
            self.logger.critical(f'tenable: QUITTING PROGRAM!!!!!!')
            quit()
        else:
            sc_dat = loads(data_req.content).get("response").get('results')

        sc_pd = pd.DataFrame(sc_dat)
        # normalize
        sc_pd = sc_pd.applymap(lambda x: x.lower() if isinstance(x, str) else x)
        sc_pd.rename(columns={'macAddress': 'mac'}, inplace=True)

        # last auth run is used for human analysis to figure last time it was scanned if needed...
        sc_pd['lastAuthRunDate'] = pd.to_datetime(sc_pd['lastAuthRun'], unit='s').dt.date  # for last credentialed scan dates
        sc_pd['lastAuthRunDate'] = sc_pd['lastAuthRunDate'].apply(lambda x: str(x) if not pd.isna(x) else 'Never')

        sc_pd['lastUnauthRunDate'] = pd.to_datetime(sc_pd['lastUnauthRun'], unit='s').dt.date  # for last uncredentialed scan dates
        sc_pd['lastUnauthRunDate'] = sc_pd['lastUnauthRunDate'].apply(lambda x: str(x) if not pd.isna(x) else 'Never')

        sc_pd = sc_pd[['mac', 'severityLow', 'severityMedium', 'severityHigh', 'severityCritical', 'lastAuthRunDate', 'lastUnauthRunDate']]
        sc_pd.reset_index(inplace=True, drop=True)
        return sc_pd

    def pull_ise_info(self, ise_session):
        mnt_data_url = f'{self.ise_info["node"]}/admin/API/mnt/Session/ActiveList'
        data_req = ise_session.get(mnt_data_url)
        if data_req.status_code != 200:
            self.logger.critical(f'ise: could not reach node at {mnt_data_url}')
            self.logger.critical(f'ise: code recvd from node {data_req.status_code} \n\n CONTENT:\n\n\ {data_req.content}\n\n')
            self.logger.critical(f'ise: QUITTING PROGRAM!!!!!!')
            quit()
        else:
            ise_data = pd.read_xml(data_req.content, parser='etree')

        # normalize
        ise_data = ise_data.applymap(lambda x: x.lower() if isinstance(x, str) else x)
        return ise_data

    def push_to_ise(self, test_data=False, **kwargs):
        self.logger.info('Starting Tenable ingestion to ISE')
        ise_session = self.ise_session()
        bulk_create = f'{self.ise_info["node"]}/api/v1/endpoint/bulk'

        # since in lab we may not get the mac from an active session if not test do this as test data should prep to injest
        if not test_data:
            ten_pd = self.pull_tenable_info()
            ise_pd = self.pull_ise_info(ise_session)
            # just take the mac from ISE data and see if its in the ten df
            ten_pd['in_ise'] = ten_pd['mac'].apply(lambda x: True if x in ise_pd['calling_station_id'].tolist() else False)
            ten_pd = ten_pd[ten_pd['in_ise'] == True]
            ten_pd.drop(columns=['in_ise'], inplace=True)

        if test_data:
            from Test.tempcheck import input_generator
            ten_pd = input_generator(amount=test_data, seed=kwargs.get('test_seed'))

        ten_pd = self.prepare_tens_data(ten_pd)
        self.logger.info(f'ISE: attempting to update {len(ten_pd)} endpoints in ISE')
        # create Templates based on new endpoints
        new_endpoints = self._ise_endpoint_template(ten_pd)
        # update endpoints
        ise_session.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        # since we need to input need endpoint for test data
        update_meth = ise_session.put(bulk_create, data=new_endpoints) if not test_data else ise_session.post(bulk_create, data=new_endpoints)

        self.logger.info(f'ISE: received status code {update_meth.status_code} for trying to update {len(ten_pd)} endpoints in ISE')
        if update_meth.status_code == 200:
            self.logger.debug(f'ISE: received back ID: {loads(update_meth.content)["id"]} from ISE')

    @staticmethod
    def prepare_tens_data(ten_pd):
        # get weighted since critical is worse and normalize
        weight_system = {'severityLow': 1, 'severityMedium': 2, 'severityHigh': 3, 'severityCritical': 4}
        ten_pd[list(weight_system.keys())] = ten_pd[list(weight_system.keys())].astype(int)
        ten_pd['weighted_severity'] = ten_pd.apply(lambda row: sum(row[col] * weight_system[col] for col in weight_system), axis=1)
        # make relative scoring
        min_sev = ten_pd['weighted_severity'].min()
        max_sev = ten_pd['weighted_severity'].max()
        ten_pd['tenable_score'] = 100 * (ten_pd['weighted_severity'] - min_sev) / (max_sev - min_sev)
        ten_pd['tenable_score'] = ten_pd['tenable_score'].round(0).astype(int)
        ten_pd.sort_values(by=['tenable_score'], inplace=True)
        # drop unneeded
        bad_cols = list(weight_system.keys())
        bad_cols.append('weighted_severity')
        ten_pd.drop(columns=bad_cols, inplace=True)
        return ten_pd

    @staticmethod
    def _ise_endpoint_template(endpoints_dat: pd.DataFrame):
        endpoints_dat['customAttributes'] = endpoints_dat.apply(lambda row: {
            'Tenable Score': str(row['tenable_score']),
            'last Auth Run': row['lastAuthRunDate'],
            'last non-Auth Run': row['lastUnauthRunDate']
        }, axis=1)
        endpoints_dat['name'] = endpoints_dat['mac']
        endpoints_dat_json = endpoints_dat.to_json(orient='records', force_ascii=False)
        return endpoints_dat_json
