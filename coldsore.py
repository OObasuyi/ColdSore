from requests import Session
from json import loads, dumps
from utils import log_collector, Rutils
import pandas as pd


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
        tenable_session.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        tenable_session.headers["x-apikey"] = f"accesskey={self.tenable_info['accesskey']}; secretkey={self.tenable_info['secretkey']}"
        score_data_url = f'{self.tenable_info["node"]}/rest/analysis'
        sc_pd = pd.DataFrame([]) # holder

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
        sc_pd = sc_pd.applymap(lambda x: x.lower() if isinstance(x,str) else x)
        return sc_pd

#TODO: need to make ISE customattr for last time scanned and severity
    def pull_ise_info(self,ise_session):
        mnt_data_url = f'{self.ise_info["node"]}/admin/API/mnt/Session/ActiveList'
        ise_data = pd.DataFrame([]) # holder

        data_req = ise_session.get(mnt_data_url)
        if data_req.status_code != 200:
            self.logger.critical(f'ise: could not reach node at {mnt_data_url}')
            self.logger.critical(f'ise: code recvd from node {data_req.status_code} \n\n CONTENT:\n\n\ {data_req.content}\n\n')
            self.logger.critical(f'ise: QUITTING PROGRAM!!!!!!')
            quit()
        else:
            ise_data = pd.read_xml(data_req.content,parser='etree')
        
        # normalize
        ise_data = ise_data.applymap(lambda x: x.lower() if isinstance(x,str) else x)
        # reuse ise session
        return ise_data


    def push_to_ise(self):
        self.logger.info('Starting Tenable ingestion to ISE')
        ise_session = self.ise_session()
        ten_pd= self.pull_tenable_info()
        ise_pd= self.pull_ise_info(ise_session)
        bulk_create = f'{self.ise_info["node"]}/api/v1/endpoint/bulk'
        ise_session.headers = {"Accept": "application/json", "Content-Type": "application/json"}

        # just take the mac from ISE data and see if its in the ten df
        mac_list = ise_pd['calling_station_id'].tolist()
        ten_pd['in_ise'] = ten_pd['macAddress'].apply(lambda x: True if x in mac_list else False)

        #normalize and keep whats needed
        ten_pd = ten_pd[ten_pd['in_ise'] == True]
        ten_pd.rename(columns={'macAddress': 'mac'}, inplace=True)
        ten_pd['lastAuthRunDate'] = pd.to_datetime(ten_pd['lastAuthRun'], unit='s').dt.date
        ten_pd['lastUnauthRunDate'] = pd.to_datetime(ten_pd['lastUnauthRun'], unit='s').dt.date
        ten_pd['lastAuthRunDate'] = ten_pd['lastAuthRunDate'].apply(lambda x: str(x) if not pd.isna(x) else 'Never')
        ten_pd['lastUnauthRunDate'] = ten_pd['lastUnauthRunDate'].apply(lambda x: str(x) if not pd.isna(x) else 'Never')
        ten_pd = ten_pd[['mac','severityLow', 'severityMedium', 'severityHigh', 'severityCritical','lastAuthRunDate','lastUnauthRunDate']]
        ten_pd.reset_index(inplace=True,drop=True)
        
        # create Templates based on new endpoints
        new_endpoints = self._ise_endpoint_template(ten_pd)

        self.logger.info(f'ISE: attempting to update {len(ten_pd)} endpoints in ISE')

        # update endpoints
        update_meth = ise_session.put(bulk_create, data=new_endpoints)
        self.logger.info(f'ISE: received status code {update_meth.status_code} for trying to update {len(ten_pd)} endpoints in ISE')
        if update_meth.status_code == 200:
            self.logger.debug(f'ISE: received back ID: {loads(update_meth.content)["id"]} from ISE')

        
    @staticmethod
    def _ise_endpoint_template(endpoints_dat: pd.DataFrame):
        endpoints_dat['customAttributes'] = endpoints_dat.apply(lambda row: {
                                                                            'severity Low': row['severityLow'], 
                                                                            'severity Medium': row['severityMedium'],
                                                                            'severity High': row['severityHigh'],
                                                                            'severity Critical': row['severityCritical'] , 
                                                                            'last Auth Run': row['lastAuthRunDate'] ,
                                                                            'last non-Auth Run': row['lastUnauthRunDate'] },
                                                                            axis=1)
        endpoints_dat['name'] = endpoints_dat['mac']
        endpoints_dat_json = endpoints_dat.to_json(orient='records', force_ascii=False)
        return endpoints_dat_json
