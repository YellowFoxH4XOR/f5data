"""F5 Quarterly Security Notification + EOL/lifecycle data scraper.

my.f5.com is a Salesforce Lightning SPA whose article bodies live inside
shadow DOM, so content is extracted with a headless browser (Playwright) that
runs a shadow-piercing JS routine and returns fully structured table data.
Parsing then happens in pure Python over that structured data.
"""

__version__ = "0.1.0"
