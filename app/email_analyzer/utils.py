import re
import requests



def extract_domain(email):

    match = re.search(
        r'@([\w\.-]+)',
        email
    )

    if match:

        return match.group(1)

    return None




def get_ip_location(ip):

    try:

        response = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=5
        )

        data = response.json()


        return {

            "IP": ip,

            "Country": data.get(
                "country_name",
                "Unknown"
            ),

            "City": data.get(
                "city",
                "Unknown"
            ),

            "ISP": data.get(
                "org",
                "Unknown"
            )

        }


    except Exception:

        return {

            "IP": ip,

            "Country": "Unknown",

            "City": "Unknown",

            "ISP": "Unknown"

        }




def analyze_email(header_text):


    result = {


        "From": "Not Available",

        "To": "Not Available",

        "Subject": "Not Available",

        "Date": "Not Available",

        "Return-Path": "Not Available",

        "Message-ID": "Not Available",


        "Received": [],


        "Sender IP": [],


        "IP Location": [],


        "SPF": "Not Found",


        "DKIM": "Not Found",


        "DMARC": "Not Found",


        "Findings": [],


        "Risk Score": 0,


        "Risk Level": "LOW"


    }



    lines = header_text.splitlines()



    for line in lines:


        lower = line.lower()



        if lower.startswith("from:"):


            result["From"] = line.split(":",1)[1].strip()



        elif lower.startswith("to:"):


            result["To"] = line.split(":",1)[1].strip()



        elif lower.startswith("subject:"):


            result["Subject"] = line.split(":",1)[1].strip()



        elif lower.startswith("date:"):


            result["Date"] = line.split(":",1)[1].strip()



        elif lower.startswith("return-path:"):


            result["Return-Path"] = line.split(":",1)[1].strip()



        elif lower.startswith("message-id:"):


            result["Message-ID"] = line.split(":",1)[1].strip()



        elif lower.startswith("received:"):


            result["Received"].append(line)



            ips = re.findall(

                r'\b(?:\d{1,3}\.){3}\d{1,3}\b',

                line

            )



            for ip in ips:



                if ip not in result["Sender IP"]:


                    result["Sender IP"].append(ip)



                    location = get_ip_location(ip)


                    result["IP Location"].append(

                        location

                    )





        elif "spf=" in lower:



            if "pass" in lower:

                result["SPF"] = "PASS"


            elif "fail" in lower:

                result["SPF"] = "FAIL"





        elif "dkim=" in lower:



            if "pass" in lower:

                result["DKIM"] = "PASS"


            elif "fail" in lower:

                result["DKIM"] = "FAIL"





        elif "dmarc=" in lower:



            if "pass" in lower:

                result["DMARC"] = "PASS"


            elif "fail" in lower:

                result["DMARC"] = "FAIL"





    # Spoofing Detection


    from_domain = extract_domain(

        result["From"]

    )


    return_domain = extract_domain(

        result["Return-Path"]

    )



    if from_domain and return_domain:



        if from_domain != return_domain:


            result["Findings"].append(

                "From domain and Return-Path domain mismatch"

            )


            result["Risk Score"] += 40





    if result["SPF"] == "FAIL":


        result["Findings"].append(

            "SPF authentication failed"

        )


        result["Risk Score"] += 20





    if result["DKIM"] == "FAIL":


        result["Findings"].append(

            "DKIM authentication failed"

        )


        result["Risk Score"] += 20





    if result["DMARC"] == "FAIL":


        result["Findings"].append(

            "DMARC authentication failed"

        )


        result["Risk Score"] += 20






    # Risk Level


    if result["Risk Score"] >= 70:


        result["Risk Level"] = "HIGH"



    elif result["Risk Score"] >= 40:


        result["Risk Level"] = "MEDIUM"



    else:


        result["Risk Level"] = "LOW"



    return result