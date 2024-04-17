from requests import Session
from json import loads, dumps
from utils import log_collector, Rutils
import pandas as pd



class ColdSore:
    UTILS = Rutils()

    def __init__(self, config: str = "config.yaml", verify_ssl=False):
        self.logger = log_collector(file_name='hazbag.log', func_name='ColdSore')
        # move config file to new folder
        config = self.UTILS.create_file_path('configs', config)
        self.config = self.UTILS.get_yaml_config(config, self)
        self.ssl_verify = verify_ssl

    
    def pull_tenable_info(self):
        tenable_info = self.config['TENABLE']
        tenable_info = Session()
        tenable_info.verify = self.ssl_verify
        tenable_info.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        tenable_info.headers["x-apikey"] = f"accesskey={tenable_info['accesskey']}; secretkey={tenable_info['secretkey']}"
        score_data_url = f'{tenable_info["node"]}/rest/analysis'
        sc_pd = pd.DataFrame([]) #holder

        req_score_data = {
            "type": "vuln",
            "query": {"id": tenable_info['query_id']},
            "sourceType": "cumulative"
        } 
        # pull data from SC
        data_req = tenable_info.post(score_data_url, data=req_score_data)
        if data_req.status_code != 200:
            self.logger.critical(f'tenable: could not reach node at {score_data_url}')
            self.logger.critical(f'tenable: code recvd from node {data_req.status_code} \n\n CONTENT:\n\n\ {data_req.content}\n\n')
            self.logger.critical(f'tenable: QUITTING PROGRAM!!!!!!')
            quit()
        else:
            sc_dat = json.loads(data_req.content).get("response").get('results')
        
        sc_pd = pd.Dataframe(sc_dat)
        # normalize and remove unneeded.
        return sc_pd

#TODO: need to make ISE customattr for last time scanned and severity

    


if __name__ == "__main__":
    coldS = ColdSore('config_test.yaml')
    coldS.pull_tenable_info()
