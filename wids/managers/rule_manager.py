from utils.config import config
from analyze.rules import Rule
from managers import log_manager

import json
import yaml
import glob

class RuleParser:
    def __init__(self):
        self._rules = []
        self._loaded = set()

    def init(self):
        if config.rule_dir is None:
            log_manager.warn(f'no rule directory specified - no rules loaded!')
            return

        for rf in glob.glob(config.rule_dir + '*.yaml'):
            # Skip rule files in ruleignore
            curr_rulefile = rf.strip().split('/')[-1]
            if curr_rulefile in config.ruleignore:
                continue

            # Load rule file
            with open(rf) as f:
                log_manager.info(f'Loading {curr_rulefile}')
                rules = yaml.safe_load(f)
                
                count = len(rules['rules'])
                for i, _rule in enumerate(rules['rules']):
                    
                    try:
                        # Check if rule is not duplicated
                        rule = Rule(_rule)
                        if rule.id in self._loaded:
                            log_manager.warn(f'duplicate rule id ({rule.id}) - skipping')
                            continue

                        self._rules.append(rule)
                        self._loaded.add(rule.id)

                    # Rule in bad format yada yada
                    except Exception as e:
                        log_manager.warn(f'could not load rule [{i}/{count}] in rule file {rf}')
                        log_manager.warn(str(e))
        
        log_manager.info(f'Loaded {len(self._rules)} rules.')
        
    def rules(self):
        return self._rules

rule_parser = RuleParser()

def get():
    return rule_parser
