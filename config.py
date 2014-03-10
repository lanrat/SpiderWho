'''Python module to contain all configuration settings for SpiderWho'''
DEBUG = True

DOMAIN_LIST = None
PROXY_LIST = None

RESULT_VALIDCHECK = False
SKIP_DONE = False
PRINT_STATUS = True
SAVE_LOGS = False

OUTPUT_FOLDER = "out/"
RESULTS_FOLDER = "results/"
LOG_FOLDER = "logs/"
FAIL_FILENAME = "fail.txt"

SAVE_EXT = "whois"
LOG_EXT = "log"

NUM_PROXIES = 0
MAX_QUEUE_SIZE = 10000

MIN_RESPONSE_LINES = 4

'''setting this value to less than 2 will greatly reduce the reliability of the program'''
MAX_ATTEMPTS = 3
RATELIMIT_ATTEMPTS = 5

STATUS_UPDATE_DELAY = 1.0

START_TIME = 0

WHOIS_SERVER_SLEEP_DELAY = 5
WHOIS_SERVER_JUMP_DELAY = 20

EMAIL_REGEX = r'[\w.-]+@[\w.-]+'

'''
list of servers who are known to be VERY strict with whois data
'''
STRICT_SERVERS = [
       "org.whois-servers.net",
       "whois.godaddy.com"
        ]

