import streamlit as st
import re
import dns.resolver
import smtplib
import pandas as pd

# Email validation functions
def validate_email_syntax(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None

def get_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [str(mx.exchange) for mx in mx_records]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return []
    except Exception as e:
        st.error(f"Error while checking MX records for {domain}: {e}")
        return []

def validate_email_domain(email):
    domain = email.split('@')[-1]
    mx_records = get_mx_records(domain)
    return len(mx_records) > 0, mx_records

def validate_email_smtp(email, mx_records):
    if not mx_records:
        return False, "No MX records found"

    try:
        mail_server = mx_records[0]
        with smtplib.SMTP(mail_server) as server:
            server.set_debuglevel(0)
            server.helo()
            server.mail('marisudhirxcodefix@gmail.com')  # Use a generic sender address
            code, _ = server.rcpt(email)
            return code == 250, "Deliverable"
    except Exception as e:
        st.error(f"SMTP error for {email}: {e}")
        return False, str(e)

def is_valid_email(email):
    if not validate_email_syntax(email):
        return "Invalid", None, None, None

    domain_valid, mx_records = validate_email_domain(email)
    if not domain_valid:
        return "Invalid", None, None, None

    smtp_valid, smtp_status = validate_email_smtp(email, mx_records)
    if not smtp_valid:
        return "Undeliverable", None, None, smtp_status

    return "Valid", mx_records, smtp_valid, smtp_status

# Define a basic list of known spam domains
SPAM_DOMAINS = {'spamdomain.com', 'fakeemail.com'}

def is_spam_email(email):
    domain = email.split('@')[-1]
    return domain in SPAM_DOMAINS

# Utility to color the result rows
def color_rows(row):
    if row['Result'] == 'Valid':
        return ['background-color: lightgreen'] * len(row)
    elif row['Result'] == 'Undeliverable':
        return ['background-color: lightcoral'] * len(row)
    else:
        return ['background-color: lightyellow'] * len(row)

# Streamlit UI
st.title("Email Validator")

# Single Email Validation
email_input = st.text_input("Enter an email address:")
if st.button("Validate"):
    if email_input:
        result, mx_records, smtp_valid, smtp_status = is_valid_email(email_input)
        spam_status = is_spam_email(email_input)

        # Display results in a table format
        st.subheader("Validation Result")
        result_data = {
            "Email": [email_input],
            "Syntax Valid": ["Valid" if validate_email_syntax(email_input) else "Invalid"],
            "Domain Validity": ["Valid" if mx_records else "Invalid"],
            "SMTP Validity": ["Valid" if smtp_valid else "Invalid"],
            "Spam Status": ["Spam" if spam_status else "Not Spam"],
            "Result": [result]
        }

        result_df = pd.DataFrame(result_data)
        st.write(result_df.style.apply(color_rows, axis=1))

    else:
        st.warning("Please enter an email address.")

# Bulk Email Validation
st.subheader("Bulk Email Validation")
uploaded_file = st.file_uploader("Upload a CSV file with emails (column named 'email')", type='csv')

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    results = []

    for email in df['email']:
        result = "Invalid"
        if validate_email_syntax(email):
            domain_valid, mx_records = validate_email_domain(email)
            smtp_valid, smtp_status = validate_email_smtp(email, mx_records) if domain_valid else (False, "No MX records found")
            result = 'Valid' if smtp_valid else 'Undeliverable'

        spam_status = is_spam_email(email)
        
        # Append the results for each email
        results.append({
            'Email': email,
            'Syntax Valid': "Valid" if validate_email_syntax(email) else "Invalid",
            'Domain Validity': "Valid" if mx_records else "Invalid",
            'SMTP Validity': "Valid" if smtp_valid else "Invalid",
            'Spam Status': "Spam" if spam_status else "Not Spam",
            'Result': result
        })

    # Convert the results to DataFrame and display
    results_df = pd.DataFrame(results)
    st.write("Validation Results")
    st.write(results_df.style.apply(color_rows, axis=1))
