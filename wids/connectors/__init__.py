""" Connectors:
  - they connect the wids with external information systems, that may add 
    additional information to the generated alerts.
  - Some example use-cases:
        - mac address to vendor translation
        - mac-to-ip resolving for ip-level alert correlation
        - external blacklists
        - and many more ... (i cannot think of any more)
"""
import connectors.macapi

connectors = {
    'macapi': connectors.macapi
}
