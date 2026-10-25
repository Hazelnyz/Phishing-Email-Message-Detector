"""
generate_dataset.py
--------------------
Generates a fully SYNTHETIC, labelled dataset of phishing and legitimate
messages for PhishGuard AI.

IMPORTANT: Every message in this dataset is synthetically authored for this
project. No real messages, real student data, or real VIT communications are
used. Template phrases are combined programmatically with randomised
variables (names, fake domains, fake amounts, fake dates) to produce a
diverse corpus. See DATASET_README.md for full documentation.

Usage:
    python src/generate_dataset.py
"""

import csv
import random
import os

random.seed(42)

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(OUT_DIR, exist_ok=True)

FIRST_NAMES = ["Rahul", "Aditi", "Karthik", "Sneha", "Arjun", "Priya", "Vikram",
               "Ananya", "Suresh", "Divya", "Manoj", "Kavya", "Rohit", "Meera",
               "Aakash", "Nisha", "Varun", "Pooja", "Siddharth", "Lakshmi"]

LEGIT_DOMAINS = ["vit.ac.in", "vitstudent.ac.in", "outlook.com", "gmail.com",
                  "icloud.com", "protonmail.com"]

FAKE_SUSPICIOUS_DOMAINS = [
    "vit-portal-verify.com", "vitstudent-login.net", "vit.accounts-secure.info",
    "edu-verify-center.xyz", "student-helpdesk-alert.com", "vit-eduportal.co",
    "secure-vit-update.org", "university-alert-system.ru", "campus-verify.top",
    "vit.ac.in.login-secure.com", "accounts-verification.site",
]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"]

# ---------------------------------------------------------------------------
# PHISHING MESSAGE TEMPLATES (synthetic, by category)
# ---------------------------------------------------------------------------

phishing_templates = []

# 1. Account suspension / urgency threats (mirrors the reported scenario)
account_suspension = [
    "URGENT: Your VIT student account will be SUSPENDED in 24 hours unless you verify your login at {url}. Act now to avoid permanent loss of access.",
    "Dear {name}, your university portal access has been flagged for suspension. Click {url} immediately to confirm your identity and avoid deactivation.",
    "ATTENTION {name}: Unusual activity detected on your student account. Verify now at {url} or your account will be permanently locked within 12 hours.",
    "Your VIT email account is scheduled for suspension today due to a security violation. Confirm your credentials here: {url}",
    "Final warning: failure to verify your student ID at {url} within 24 hours will result in immediate account termination.",
    "Your access to the student portal has been temporarily restricted. Restore it instantly by logging in at {url} before midnight.",
    "We detected a policy violation on your account. To prevent suspension, verify your details urgently at {url}.",
    "Immediate action required: your university account password has expired and must be reset at {url} within the next 2 hours or access will be revoked.",
]

# 2. Credential / password / OTP requests
credential_requests = [
    "Hi {name}, this is IT Support. Please reply with your student portal password so we can complete the security audit.",
    "To verify your identity, send us the OTP you just received along with your registration number.",
    "Your bank has sent a one-time password to your phone. Please share the OTP with our verification agent at {url} to unlock your scholarship disbursement.",
    "We need your login password to migrate your email to the new VIT server. Reply with your current password to proceed.",
    "Confirm your identity by entering your username and password at {url}. This is mandatory for all final-year students.",
    "Please provide the 6-digit OTP sent to your registered mobile number to complete your exam hall ticket verification.",
    "Our system requires your current password for a routine security check. Reply to this message with your credentials.",
]

# 3. Fake scholarships / financial lures
fake_scholarship = [
    "Congratulations {name}! You have been selected for a merit scholarship of Rs. 50,000. Claim it now at {url} before the offer expires.",
    "VIT Scholarship Cell: You are eligible for an emergency fee waiver. Submit your bank details at {url} to receive the amount today.",
    "Good news {name}! Your scholarship application has been approved. Pay a small processing fee of Rs. 499 at {url} to release the funds.",
    "You've won a government education grant of Rs. 25,000. Claim your prize by entering your account number at {url} within 48 hours.",
    "Limited slots left for the Vellore merit scholarship. Register with your card details at {url} to lock in your reward.",
    "Your scholarship refund of Rs. 12,500 is pending. Click {url} and enter your UPI PIN to receive it instantly.",
]

# 4. Suspicious links / fake notifications with shortened/odd URLs
suspicious_links = [
    "Check out this important update about your semester results: {url}",
    "Your exam hall ticket is ready for download: {url}",
    "New fee payment portal is live. Pay your pending dues here: {url}",
    "Important: library fine notice attached. View details at {url}",
    "Your placement drive registration link: {url}. Limited seats, apply fast.",
    "Click here to see your updated CGPA report: {url}",
    "Your hostel room allocation has changed. Confirm your new room at {url}",
]

# 5. Payment requests
payment_requests = [
    "Your semester fee payment failed. Resend payment of Rs. 85,000 immediately via {url} to avoid late fine.",
    "Pending lab fee of Rs. 3,500 must be paid today at {url} or your exam registration will be cancelled.",
    "Please transfer the refundable caution deposit of Rs. 10,000 to the account linked at {url} to confirm your admission.",
    "Your convocation fee of Rs. 2,000 is overdue. Pay now at {url} using any UPI app to avoid certificate hold.",
]

# 6. Sender mismatch / spoofed authority
sender_mismatch = [
    "This is the Dean's office. We require you to verify your academic record immediately at {url}, otherwise your degree will be withheld.",
    "Message from VIT Examination Controller: your hall ticket has been suspended. Resolve at {url} within 6 hours.",
    "Official notice from the Registrar: your enrolment status is under review. Confirm your details at {url} today.",
    "This is an automated alert from the VIT IT Security Team. Your mailbox will be disabled unless you re-authenticate at {url}.",
]

phishing_groups = [account_suspension, credential_requests, fake_scholarship,
                    suspicious_links, payment_requests, sender_mismatch]

# Additional families vary the social framing and keep whole styles holdable.
polite_phishing = [
    "Could you kindly confirm your account password at {url} so we can finish the routine update?",
    "When convenient, please share your OTP and card number at {url} to complete the reimbursement.",
    "We would appreciate your UPI PIN to release the scholarship refund at {url}.",
]
sms_phishing = [
    "acct verify pls send ur otp at {url} or access stop",
    "gimme ur card cvv to process refund {url}",
    "plz confirm acct pwd now {url}",
]
sender_mismatch_requests = [
    "A message claiming to be from the registrar asks for your PAN details at {url}.",
    "Payroll requests your bank acct number and IFSC at {url} for a correction.",
    "Campus IT asks you to reply with your net banking login at {url}.",
]
phishing_groups.extend([polite_phishing, sms_phishing, sender_mismatch_requests])

# ---------------------------------------------------------------------------
# LEGITIMATE MESSAGE TEMPLATES
# ---------------------------------------------------------------------------

legit_university_notifications = [
    "Dear {name}, your semester timetable has been published on VTOP. Please check your schedule under the academics tab.",
    "Reminder: the Continuous Assessment Test (CAT-2) begins next Monday. Please check your seating arrangement on VTOP.",
    "The library will remain open until 10 PM during the exam period. Plan your study sessions accordingly.",
    "Dear {name}, your internal assessment marks have been updated on VTOP. Please review them and contact your faculty advisor for queries.",
    "The annual technical symposium registrations are now open. Visit the student activity center for more details.",
    "Hostel maintenance work is scheduled for this weekend in Block C. Water supply may be interrupted between 10 AM and 2 PM.",
    "Dear {name}, your course registration for the upcoming semester is now open on VTOP until Friday.",
    "The placement cell has scheduled a pre-placement talk by a visiting company next Wednesday in the main auditorium.",
    "Reminder: submit your project synopsis to your guide before the end of this week.",
    "Dear {name}, your attendance percentage for this semester has been updated. Please check VTOP for details.",
    "Dear {name}, the FAT (Final Assessment Test) schedule has been released. Please download your hall ticket from VTOP after verifying your eligibility.",
    "The academic calendar for next semester has been uploaded to the student portal. Please review the revised holiday list.",
    "Dear {name}, your supervisor has reviewed your project report and left comments on VTOP. Please check and revise accordingly.",
    "The university will conduct a fire safety drill in all hostel blocks this Thursday at 4 PM.",
    "Dear {name}, you have been shortlisted for the student exchange program interview. Details will be shared by the international relations office.",
    "The sports committee is organizing intra-college trials next week. Interested students can register at the sports complex.",
    "Dear {name}, your re-evaluation request for the mid-term exam has been processed. Results will be updated within 10 working days.",
    "The guest lecture on distributed systems, originally scheduled for Monday, has been moved to Wednesday in Seminar Hall 2.",
    "Dear {name}, please collect your corrected answer scripts from your respective faculty during the next class.",
    "The cultural fest committee is looking for volunteers. Sign-up sheets are available at the student activity center.",
    "Dear {name}, your name has been added to the dean's merit list for this semester. Congratulations.",
    "A blood donation camp will be held in the main auditorium next Friday, organized by the NSS unit.",
    "Dear {name}, kindly submit your internship completion certificate to the department office by the end of this month.",
]

legit_personal_messages = [
    "Hey {name}, are we still meeting for the group project discussion at 5 PM today?",
    "Can you send me your notes from today's class? I missed the lecture.",
    "Thanks for helping me with the assignment yesterday, really appreciate it!",
    "Are you free this weekend? A few of us are planning to watch a movie.",
    "Did you submit the lab report yet? The deadline is tomorrow night.",
    "Let's meet at the canteen before the next class, I need to discuss something.",
    "Congrats on your internship offer! That's really exciting news.",
    "Can you share the reference book PDF for the course?",
    "I'll be a bit late to the meeting, stuck in the shuttle queue.",
    "Happy birthday! Hope you have a great day, let's catch up soon.",
    "Hey {name}, did you understand the recursion topic from today's lecture? Can you explain it to me?",
    "Are you joining the coding club meetup this evening?",
    "I left my charger in the library, did you happen to see it?",
    "Good luck for your presentation tomorrow, you'll do great!",
    "Can we reschedule our study session to 7 PM instead of 6?",
    "Hey, thanks for lending me your laptop charger yesterday.",
    "Did you hear back from the internship you applied to?",
    "Let's split the cab fare to the railway station this weekend.",
    "Can you proofread my resume before I send it out?",
    "Hey {name}, want to grab lunch after the next lecture?",
    "I'm stuck on this assignment question, can you help me out when you're free?",
    "Thanks for covering my shift at the club event, I owe you one.",
]

legit_service_notifications = [
    "Your food order from the campus cafe has been confirmed and will arrive in 20 minutes.",
    "Your monthly electricity bill of Rs. 1,200 has been generated. You can view it by logging into your utility provider's official app.",
    "Your flight booking is confirmed. Check-in opens 48 hours before departure.",
    "Your package has been shipped and is expected to arrive in 3-5 business days.",
    "Thank you for your purchase. Your invoice has been emailed to your registered address.",
    "Your subscription renewal was successful. No action is needed from your side.",
    "Your appointment with the campus health center has been scheduled for tomorrow at 11 AM.",
    "Your recent transaction of Rs. 450 at the campus store was successful.",
    "Your ride has arrived. Please proceed to the pickup point.",
    "Your laundry order will be delivered to your hostel room by 6 PM today.",
    "Your mobile recharge of Rs. 199 was successful. Validity extended by 28 days.",
    "Your gym membership has been renewed for another 3 months.",
    "Your printout order at the stationery shop is ready for pickup.",
    "Your movie tickets for tonight's show have been booked successfully.",
    "Your water purifier filter replacement is due this week; contact the hostel maintenance desk to schedule it.",
    "Your online grocery order has been delivered to the hostel reception.",
]

legit_groups = [legit_university_notifications, legit_personal_messages,
                 legit_service_notifications]

legit_urgent_notices = [
    "Urgent: the exam hall changes to Block C today. Confirm the room in the campus app.",
    "Final reminder: library books are due by 6 PM today. Renew them in the library portal.",
    "Road closure begins in 30 minutes. Check the city transport authority site for the detour.",
]
legit_informal_requests = [
    "could u pass me the lab record after class", "gimme the lecture notes when u can",
    "plz share your timetable for next week", "send the group project doc whenever",
]
legit_link_notices = [
    "Your appointment is confirmed. Review the details in the official clinic app.",
    "The campus event schedule is updated at https://vit.ac.in/events.",
    "Your parcel is out for delivery. Track it in the courier's official application.",
]
legit_groups.extend([legit_urgent_notices, legit_informal_requests, legit_link_notices])


def make_url(suspicious: bool) -> str:
    if suspicious:
        domain = random.choice(FAKE_SUSPICIOUS_DOMAINS + SHORTENER_DOMAINS)
        path = random.choice(["verify", "login", "secure", "confirm", "account/update", "claim"])
        return f"http://{domain}/{path}?id={random.randint(1000,9999)}"
    else:
        domain = random.choice(LEGIT_DOMAINS)
        return f"https://{domain}/portal"


def add_message_variation(text: str) -> str:
    """Seeded style noise: casing and common SMS substitutions."""
    if random.random() < 0.18:
        text = text.replace("your", random.choice(["ur", "u'r"]))
    if random.random() < 0.12:
        text = text.replace("please", random.choice(["pls", "plz"]))
    if random.random() < 0.08:
        text = text.replace("account", "acct")
    if random.random() < 0.08:
        text = text.swapcase() if random.random() < 0.5 else text.upper()
    if random.random() < 0.05:
        text = text.replace("verify", "verfy")
    return text


COURSES = ["Database Management Systems", "Data Structures", "Operating Systems",
           "Computer Networks", "Machine Learning", "Software Engineering",
           "Theory of Computation", "Cloud Computing", "Cryptography"]

TIME_PHRASES = ["within 2 hours", "within 6 hours", "within 12 hours",
                "within 24 hours", "by tonight", "by tomorrow morning",
                "before midnight", "within 48 hours", "immediately",
                "before the deadline"]


def generate_rows(n_phishing=300, n_legit=300, max_attempts_multiplier=50):
    rows = []
    seen = set()

    # Phishing: sample across all templates with varied names/urls/time phrases
    attempts = 0
    while len([r for r in rows if r["label"] == "phishing"]) < n_phishing and \
            attempts < n_phishing * max_attempts_multiplier:
        attempts += 1
        group_index = random.randrange(len(phishing_groups))
        group = phishing_groups[group_index]
        template = random.choice(group)
        name = random.choice(FIRST_NAMES)
        url = make_url(suspicious=True)
        text = template.format(name=name, url=url)
        # inject variety by occasionally prefixing/suffixing a time phrase
        if random.random() < 0.3 and "{name}" not in template:
            text = f"{text} Respond {random.choice(TIME_PHRASES)}."
        text = add_message_variation(text)
        if text not in seen:
            seen.add(text)
            rows.append({"message": text, "label": "phishing", "family": f"phishing_{group_index}"})

    # Legit: sample across all templates with varied names/urls/courses
    attempts = 0
    while len([r for r in rows if r["label"] == "legitimate"]) < n_legit and \
            attempts < n_legit * max_attempts_multiplier:
        attempts += 1
        family_index = random.randrange(len(legit_groups) * 2)
        group = legit_groups[family_index // 2]
        template = random.choice(group)
        name = random.choice(FIRST_NAMES)
        if "{url}" in template:
            url = make_url(suspicious=False)
            text = template.format(name=name, url=url)
        else:
            text = template.format(name=name)
        if random.random() < 0.25:
            text = text.replace("class", random.choice(COURSES) + " class") \
                if "class" in text else text
        text = add_message_variation(text)
        if text not in seen:
            seen.add(text)
            rows.append({"message": text, "label": "legitimate", "family": f"legitimate_{family_index}"})

    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    rows = generate_rows(n_phishing=300, n_legit=300)

    # Keep whole template families together. Families 4/2 are test holdouts;
    # families 5/1 are validation holdouts. Seeded generation is reproducible.
    family_ids = sorted({r["family"] for r in rows})
    train_rows, validation_rows, test_rows = [], [], []
    for label, count in (("phishing", len(phishing_groups)), ("legitimate", len(legit_groups) * 2)):
        families = [f"{label}_{i}" for i in range(count)]
        for idx, family in enumerate(families):
            target = test_rows if idx == count - 1 else validation_rows if idx == count - 2 else train_rows
            target.extend(r for r in rows if r["family"] == family)
    full_rows = train_rows + validation_rows + test_rows
    random.shuffle(train_rows)
    random.shuffle(validation_rows)
    random.shuffle(test_rows)
    # A conventional message-level holdout complements the family holdout.
    random.shuffle(train_rows)
    standard_test_rows = train_rows[:len(train_rows) // 5]
    train_rows = train_rows[len(train_rows) // 5:]

    full_path = os.path.join(OUT_DIR, "messages_full.csv")
    train_path = os.path.join(OUT_DIR, "train.csv")
    test_path = os.path.join(OUT_DIR, "test.csv")
    validation_path = os.path.join(OUT_DIR, "validation.csv")
    standard_test_path = os.path.join(OUT_DIR, "standard_test.csv")

    for path, data in [(full_path, full_rows),
                        (train_path, train_rows),
                        (validation_path, validation_rows),
                        (standard_test_path, standard_test_rows),
                        (test_path, test_rows)]:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["message", "label", "family"])
            writer.writeheader()
            writer.writerows(data)

    print(f"Total rows: {len(train_rows) + len(test_rows)}")
    print(f"Train rows: {len(train_rows)}")
    print(f"Validation rows: {len(validation_rows)}")
    print(f"Test rows:  {len(test_rows)}")
    print(f"Saved to: {full_path}, {train_path}, {test_path}")
