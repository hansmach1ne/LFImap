from urllib.parse import urlsplit, parse_qsl, parse_qs, urlparse
from src.utils.arguments import args
import json
import re
from src.configs import config

import itertools

# Check if there is a new line after the headers in reqfile. Return boolean.
def is_file_ending_with_newline(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    # Find the index of the first empty line, which indicates the end of headers
    index = content.find('\n\n')

    if index != -1 and index < len(content) - 1:
        return True
    else:
        return False

def is_valid_url(url):
	urlRegex = re.compile(
		r'^(?:http|ftp)s?://' # http:// or https:// or ftp://
		r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
		r'localhost|' #localhost...
		r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
		r'(?::\d+)?' # optional port
		r'(?:/?|[/?]\S+)$', re.IGNORECASE)

	if(re.match(urlRegex, url)):
		return True
	else: return False

def is_valid_json(data):
	try:
		json.loads(data)
		return True
	except json.JSONDecodeError:
		return False
		
def getDictKey(dictionary, n):
	keys = list(dictionary.keys())
	return keys[n]

def getDictValue(dictionary, n):
	values = list(dictionary.values())
	return values[n]

def convert_http_formdata_to_json(formdata):
	items = formdata.split('&')
	parsed_data = {}
	for item in items:
		key_value = item.split('=')
		key = key_value[0]
		value = key_value[1] if len(key_value) > 1 else ''
		parsed_data[key] = value
	json_data = json.dumps(parsed_data)
	return json_data

def parse_http_request_file(file_path):
	try:
		with open(file_path, "r") as file:
			http_request = file.read()
			headers, post_data = http_request.split("\n\n", 1)  # Split into headers and POST data
			header_lines = headers.split("\n")
			method, endpoint, protocol = header_lines[0].split(" ", 2)

			# Parse headers
			headers_dict = {}
			for line in header_lines[1:]:
				header_name, header_value = line.split(":", 1)
				headers_dict[header_name.strip()] = header_value.strip()

			config.postreq = post_data.strip()
			form_data = parseFormDataLine(post_data.strip())
			
			return method, headers_dict, form_data

	except Exception as e:
		print(f"Error parsing HTTP request: {e}")
		return None

def is_string_in_dict(s, my_dict):
    for key, value in my_dict.items():
        if s in str(key) or s in str(value):
            return True
    return False

def parse_url_parameters(url):
	parsed_url = urlparse(url)
	query_parameters = parse_qs(parsed_url.query)
	
	parameter_names = list(query_parameters.keys())
	parameter_names_combined = ', '.join(parameter_names)
	
	return parameter_names_combined

def parse_url_from_request_file(file_path, force_ssl=False):
	try:
		with open(file_path, "r") as file:
			http_request = file.read()
			lines = http_request.split("\n")
			get_request_line = lines[0]
			parts = get_request_line.split(" ", 2)
			if len(parts) == 3:
				method, endpoint, protocol = parts
			else:
				method, endpoint = parts
				protocol = ""
			url_parts = endpoint.split("?", 1)
			path = url_parts[0]
			query_string = url_parts[1] if len(url_parts) > 1 else ""
			query_params = []
			if query_string:
				params = query_string.split("&")
				for param in params:
					if "=" in param:
						name, value = param.split("=")
					else:
						name = param
						value = ""
					query_params.append(f"{name}={value}")
			host_line = next((line for line in lines if line.startswith("Host:")), None)
			if host_line:
				host = host_line.split(": ", 1)[1]
			else:
				raise Exception("Host header not found in the request.")

			if args.force_ssl:
				url = f"https://{host}{path}"
			else:
				url = f"http://{host}{path}"
			if query_params:
				url += f"?{'&'.join(query_params)}"

			return url
	except FileNotFoundError:
		raise Exception("File not found. Please provide a valid file path.")
	except Exception as e:
		raise Exception("An error occurred while parsing the request:", str(e))

def parseGet(url):
	placeholder = {}
	testUrls = []
	#Dictionary of GET parameters
	getParams = get_all_params(url)

	if(len(getParams) == 0):
		return [url]

	u = urlparse(url)
	query = parse_qs(u.query)

	scheme = u.scheme
	creds = u.netloc
	path = u.path
	q = query

	baseUrl = ""
	baseUrl += scheme
	baseUrl += "://"
	baseUrl += creds
	baseUrl += path

	for test in getParams.keys():		   
		testParameter = "".join(test)
		recreated = baseUrl
		

		if(testParameter == ""):
			testUrls.append(recreated)
			break

		c = 0
		for k, v in getParams.items():
			if(c == 0): recreated += "?"
			else: recreated += "&"

			recreated += "".join(k)
			recreated += "="
			if("".join(k) == testParameter):
				recreated += args.param #PWN
			else: 
				num = len(v)
				tmp = 0
				
				# If parameter is not passed as array
				if(num <= 1):
					v = list(itertools.chain(*v))
					recreated += "".join(v)

				# Multiple parameters are passed with same name (as array)
				else:
					for item in v:
						if(tmp != 0): recreated += "&" + "".join(k) + "="
						recreated += args.param #PWN
						tmp += 1
			c+= 1

		testUrls.append(recreated)

	# Return list of urls parsed and ready to be tested with PWN placeholders
	return testUrls

def parseFormDataLine(postData):
	if(postData == ""): return ""

	parameters = postData.split("&")
	num_parameters = len(parameters)
	testParams = []

	for i in range(num_parameters):
		temp_params = []

		for idx, parameter in enumerate(parameters):
			name_value_pair = parameter.split("=")
			name = name_value_pair[0]
			value = "PWN" if idx == i else (name_value_pair[1] if len(name_value_pair) > 1 else "")

			prepareString = f"{name}={value}"
			temp_params.append(prepareString)

		testParams.append('&'.join(temp_params))

	return testParams


def get_all_params(url):
	query_string = urlsplit(url).query
	params = {}
	for param in query_string.split('&'):
		if '=' in param:
			key, value = param.split('=', 1)
		else:
			key, value = param, ['']
		params[key] = [value]
	return params

def get_params_with_param(url):
	query_string = urlsplit(url).query
	params = dict(parse_qsl(query_string))

	matching_params = [key for key, value in params.items() if args.param in value]
	return ", ".join(matching_params)

def post_params_with_param(url):
	parsed_params = parse_qs(url)
	params = dict(parse_qsl(url))

	params_with_pwn_value = [param for param, value in parsed_params.items() if args.param in value[0]]
	result = ", ".join(params_with_pwn_value)
	return result

def getHeadersToTest(dictionary):
 	matching_keys = [key for key, value in dictionary.items() if isinstance(value, bytes) and args.param.encode() in value]
 	return ', '.join(matching_keys)

def compare_dicts(dict1, dict2):
	# Check if the dictionaries have the same keys
	if set(dict1.keys()) != set(dict2.keys()):
		return False
	
	# Check if the values associated with each key are equal
	for key in dict1:
		if dict1[key] != dict2[key]:
			return False
	
	# If all checks pass, the dictionaries are the same
	return True
	