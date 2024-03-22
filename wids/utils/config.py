import yaml
import os
from typing import List, Tuple
import utils.defaults as defaults

class _HomeNet:
    """ """
    ssid: str = ""
    hidden: bool = False
    mac: List[str] = []
    channels: List[int] = []

    def __init__(self, cfg):
        self.ssid = cfg['ssid']
        self.hidden = cfg['hidden']
        self.mac = []
        for _m in cfg['mac']:
            self.mac.append(_m)
        self.channels = []
        for _c in cfg['channels']:
            self.channels.append(_c)

    def summary(self):
        print(' SSID:', self.ssid)
        print('       Hidden:', self.hidden)
        print('       List of MAC addresses:')
        for i,x in enumerate(self.mac):
            print(f'         - ', x)
        print('       List of channels: [', ', '.join(str(x) for x in self.channels), ']')


class _HomeDict(dict):
    def macs(self):
        macs = set()
        for k in self:
            macs.update(self[k].mac)
        return macs

    def channels(self):
        chans = set()
        for k in self:
            chans.update(self[k].channels)
        return chans

class CustomConfig:
    def __init__(self):
        self._attributes = {}

    def __getattr__(self, name):
        if name in self._attributes:
            return self._attributes[name]
        else:
            raise AttributeError(f"{type(self).__name__} does not have attribute '{name}'")
    
    def __setattr__(self, name, value):
        if name == '_attributes':
            super().__setattr__(name, value)
        else:
            if isinstance(value, dict):
                nested_obj = CustomConfig()
                for key, val in value.items():
                    setattr(nested_obj, str(key), val)
                self._attributes[name] = nested_obj
            else:
                self._attributes[name] = value

    def __iter__(self):
        return iter(self._attributes.items())

    def __dict__(self):
        return self._attributes

    def __getitem__(self, key):
        return self._attributes[key]
    
    def __setitem__(self, key, value):
        self._attributes[key] = value

class Config:
    """ """

    class ModKr00k:
        try_decrypt_kr00k: bool = False
        kr00k_alert_unknown: bool = False

    _config = {}
    
    # App config
    mode: int = 0
    trace_file: str = ""
    remote: List[Tuple[str,int]] = []
    verbose: bool = False
    output_file: str = ""

    # Wids config
    home: _HomeDict[str, _HomeNet] = _HomeDict()
    rule_file: str = ""
    rule_dir: str = ""
    ruleignore: List[str] = []
    learning_for: int = 0
    profile: str = ""
    modules: List[str] = []
    keep_for: int = 10000
    left_after: float = 120.0
    # TODO maybe levels ??
    debug: bool = False
    debug_interval: int = 10000000
    interactive: bool = True

    def __init__(self):
        self.vars = CustomConfig()

    def summary(self):
        print('** Loaded config: ', self.config_path, '**')
        print('Debug mode:', self.debug)
        print('    - summary interval:', self.debug_interval)
        print('    - interactive:', self.interactive)
        print('Mode:', self.mode)
        print('Trace file:', self.trace_file)
        print('Remotes:')
        for i,x in enumerate(self.remote):
            print(f'  [{i}]: {x[0]}:{x[1]}')
        print('Verbose:', self.verbose)
        print('Output file:', self.output_file)
        print('Home networks:')
        for i,x in enumerate(self.home):
            print(f'  [{i}]:',end='')
            self.home[x].summary()
        print('Rule dir:', self.rule_dir)
        print('Rule files to ignore:', ', '.join(self.ruleignore))
        print('Frames to keep in memory:', self.keep_for)
        print('Device idle time:', self.left_after)
        print('Learning for:', self.learning_for)
        print('Profile:', self.profile)
        print('Modules enabled:', ', '.join(self.modules))

    def init(self, _config_path):
        self.config_path = os.path.abspath(_config_path)

    def load(self):
        """ populates the config with values from file"""
        
        with open(self.config_path, 'r') as f:
            data = yaml.safe_load(f)
            self._config = data
        
        self._load_app_cfg(self._config.get('app', {}))
        self._load_wids_cfg(self._config.get('wids', {}))
        self._load_custom(self._config.get('vars', {}))
        
        self._verify_and_fix()

    def load_home(self, cfg):
        self.home = _HomeDict()
        for _h in cfg.get('home', defaults.home):
            self.home[_h['ssid']] =_HomeNet(_h)

    def load_remote(self, cfg):
        self.remote = []
        for _r in cfg.get('remote', defaults.remote):
            self.remote.append((_r['addr'], _r['port']))

    def _load_app_cfg(self, cfg):
        self.mode = cfg.get('mode', defaults.mode)
        self.trace_file = cfg.get('trace_file', defaults.trace_file)
        self.load_remote(cfg)
        self.debug = cfg.get('debug', defaults.debug)
        self.debug_interval = cfg.get('debug_interval', defaults.debug_interval)
        self.interactive = cfg.get('interactive', defaults.interactive)
        self.verbose = cfg.get('verbose', defaults.verbose)
        self.output_file = cfg.get('output_file', defaults.output_file)

    def _load_wids_cfg(self, cfg):
        self.load_home(cfg)

        self.rule_file = cfg.get('rule_file')
        self.rule_dir = cfg.get('rule_dir')
        
        if self.rule_dir is not None and self.rule_dir[-1] != '/':
            self.rule_dir += '/'

        self.ruleignore = cfg.get('ruleignore', defaults.ruleignore)
        self.learning_for = cfg.get('learning_for', defaults.learning_for)
        
        self.modules = []
        for _m in cfg.get('modules', defaults.modules):
            self.modules.append(_m)
        
        self.keep_for = cfg.get('keep_for', defaults.keep_for)
        self.left_after = cfg.get('left_after', defaults.left_after)

    def _load_custom(self, cfg):
        self.vars = CustomConfig()
        for k in cfg:
            self.vars.__setattr__(k, cfg[k])


    def _verify_and_fix(self):
        """ checks and attempts to correct any config errors """
        
        # if self.mode not in [MODE_TRACE, MODE_REALTIME]:
        #     self.mode = MODE_NONE
        # ...

        pass

    def _parse_kr00k(self, cfg):
        
        pass

config = Config()
