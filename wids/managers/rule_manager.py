import utils.context as config
from analyze.rules import Rule

import json

class RuleParser:
    def __init__(self):
        self.rules = []
        self.load()

    def load(self):
        with open(config.rule_file) as f:
            rule_file = json.load(f)
        
        for rule in rule_file['rules']:
            self.rules.append(Rule(rule))  

rule_parser = RuleParser()
