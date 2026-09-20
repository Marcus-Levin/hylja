# Example: contextual customer protection

Direct replacement is insufficient when context can re-identify the customer.

Input context may contain customer name, site, rare process description, date, and project codename. Hylja first replaces direct identifiers, then evaluates contextual re-identification risk. Policy can generalize site/date/process details until the payload preserves engineering utility without trivially revealing the original customer.
