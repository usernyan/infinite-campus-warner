import csv
import requests
from smtplib import SMTP
from smtplib import SMTPException
import configparser
import datetime
import os
import requests
from html.parser import HTMLParser
#TODO
# Log errors found in the CSV file, ex: malformed URLs
# Log every step of the process of checking if the site is up.
# Change the email's subject line if any failures occur.
# Support unique logins for each site.

def main():
    #read config file
    cfg = configparser.ConfigParser()
    cfg.read('config.ini')
    test_results = []
    with open("district_info.csv") as csv_file:
        district_sites = csv.DictReader(csv_file)
        test_results = process_sites(district_sites, cfg)
    print(test_results)
    #NOTE:

    fields_to_show = ["DISTRICT_NAME", "TEST_200_STATUS", "LOGIN_SUCCESS", "TEST_DATETIME"]
    field_name_order = ["DISTRICT_NAME", "IC_SITE", "TEST_VALID_URL", "TEST_200_STATUS", "LOGIN_SUCCESS", "TEST_DATETIME"]

    #NOTE: this message is basically the same as the csv, just with fewer fields
    #condsider replacing this with code that leverages the .csv library,
    #if the message format can be made readable
    results_table = test_results_description(test_results, fields_to_show)
    print(results_table)

    has_failure = False
    for d in test_results:
        for k in fields_to_show:
            test_val = d.get(k)
            has_failure |= test_val == False
    
    if cfg["GENERAL"].getboolean("WRITE_OUTPUT"):
        #write csv file
        out_dir = cfg["GENERAL"]["OUTPUT_DIR"]
        file_name = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".csv"
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        with open(os.path.join(out_dir, file_name), 'w', newline='') as to_write:
            writer = csv.DictWriter(to_write, field_name_order, extrasaction="ignore")
            writer.writeheader()
            for d in test_results:
                writer.writerow(d)
    
    if cfg["GENERAL"].getboolean("SEND_MAIL") or (cfg["GENERAL"].getboolean("SEND_MAIL_ON_FAIL") and has_failure):
        send_emails(results_table, cfg["MAIL_INFO"])


def test_results_description(results, to_show):
    message_text = "Here's the results of the test:\n"
    headers = ", ".join(to_show)
    failed_tests = []
    all_tests = []
    for d in results:
        cols = []
        emphasize_row = False
        for k in to_show:
            test_val = d.get(k)
            val_as_string = str(test_val)
            emphasize_row |= test_val == False
            cols.append(val_as_string)
        row_text = ", ".join(cols)
        if emphasize_row:
            failed_tests.append(row_text)
        all_tests.append(row_text)
    #failed tests
    if failed_tests != []:
        message_text += '\n' + "FAILED TESTS:\n"
        message_text += headers + "\n"
        for r in failed_tests:
            message_text += r + '\n'
    #all tests
    message_text += '\n' + "ALL TESTS:\n"
    message_text += headers + "\n"
    for r in all_tests:
        message_text += r + '\n'
    return message_text

def send_emails(message, email_info):
    subs = email_info["SUBSCRIBERS"].split(',')
    for s in subs:
        s = s.strip()
        email_info["SUBSCRIBER"] = s
        send_email(message, email_info)

def send_email(message, email_info):
    #automatically add the header
    msg_from = "From: "    + email_info["USER"]
    msg_to   = "To: "      + email_info["SUBSCRIBER"]
    msg_sub  = "Subject: " + email_info["MSG_SUBJECT"]
    msg_mime = "Mime-Type: text/plain"
    meta_msg = "\n".join([msg_from, msg_to, msg_sub, msg_mime]) + "\n\n"
    message = meta_msg + message
    print(message)
    #connect to the mail server and send the email
    try:
        with SMTP(email_info["HOST"], int(email_info["PORT"])) as smtp:
            #print(smtp.noop())
            smtp.login(email_info["USER"], email_info["PASS"])
            smtp.sendmail(email_info["USER"], email_info["SUBSCRIBER"],message)
    except SMTPException as e:
        print("Error sending email... Check your email server and config. Details below")
        print(e)

#for each site dict in the iterable, chcek if it's down. Add that as a key to the dict and return it
def process_sites(sites, config):
    #TODO
    #The requests library has a Session feature that lets cookies and headers persist between requests
    #Use this to store login info for a site.
    all_sites = []
    for d in sites:
        name = d["DISTRICT_NAME"]
        url = d["IC_SITE"]
        test_start_datetime = datetime.datetime.now()
        d["TEST_DATETIME"] = test_start_datetime
        url_is_valid = False
        is_up = False
        try:
            is_up = check_site_up(url)
            url_is_valid = True
        #TODO: log these as errors so the user knows to fix the CSV file
        except requests.exceptions.InvalidURL as e:
            print("Invalid url:", url)
        except requests.exceptions.MissingSchema as e:
            print("Missing schema (http, https):", url)
        except requests.exceptions.InvalidSchema as e:
            print("Invalid schema (http, https):", url)
        d["TEST_VALID_URL"] = url_is_valid
        if url_is_valid:
            d["TEST_200_STATUS"] = is_up
            print(name, "is", "up" if is_up else "down")
        all_sites.append(d)
        if not (url_is_valid and is_up and d["DO_LOGIN_CHECK"]):
            continue
        if d["TEST_VALID_URL"] and d["TEST_200_STATUS"]:
            d["LOGIN_SUCCESS"] = login_test(url, config["IC_INFO"])
    return all_sites

def check_site_up(url):
    status = None
    try:
        r = requests.get(url)
        status = r.status_code
    except requests.exceptions.ConnectionError as e:
        print("Connection error:", url)
    except requests.exceptions.Timeout as e:
        print("Timeout trying to reach:", url)
    except requests.exceptions.TooManyRedirects as e:
        print("Site is redirecting us too many times:", url)
    return status == 200

def login_test(site, ic_config):
    login_info = {
        "username" : ic_config["USER"],
        "password" : ic_config["PASS"],
    }
    site_verify = "/".join(site.split("/")[0:-1]) + "/verify.jsp"
    with requests.Session() as sesh:
        try:
            login_page = sesh.get(site)
        except Exception as e:
            print("Something went wrong getting the login page!")
            print(e)
            return False
        #TODO: catch parser exceptions
        parser = LoginFormParser()
        try:
            parser.feed(login_page.text)
        except Exception as e:
            print("Something went wrong with the parser!")
            print(e)
            return False
        payload = parser.inputs
        payload.update(login_info)
        try:
            p = sesh.post(site_verify, data=payload, allow_redirects=False)
        except Exception as e:
            print("Something went wrong posting the login form!")
            print(e)
            return False
        login_success = False
        if p.status_code == 302:
            redirect_loc = p.headers.get("Location")
            login_success = not redirect_loc.startswith(site)
            login_success = redirect_loc != site + "?status=password-error"
        return login_success

#This handles getting the tags out of the login input form
#That way we can use them as parameters to the post request,
#just like the browser would if logging in normally.
class LoginFormParser(HTMLParser):
    form_attrs = []
    inside_form_tag = False
    inputs = {}
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.inside_form_tag and tag == "input":
            self.remember_vals(attrs)
        if tag == "form":
            self.form_attrs = attrs
            self.inside_form_tag = True
    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.inside_form_tag = False
    def remember_vals(self, input_tag_attrs):
        name = None
        value = None
        for a in input_tag_attrs:
            if a[0] == "name":
                name = a[1]
            if a[0] == "value":
                value = a[1]
        if not (name is None or value is None):
            self.inputs[name] = value

if __name__ == '__main__':
    main()