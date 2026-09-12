import os
import re
import pickle
import random
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------------------------------
# 1. COMPREHENSIVE MULTI-VECTOR PHISHING & ENTERPRISE CORPUS
# ------------------------------------------------------------------------------

PHISHING_TEMPLATES = [
    # Enterprise HR & Workplace Policy Violations (Spear Phishing)
    "Workplace Alert: We have identified recent activity on your company-assigned device that appears to be in violation of our Device and Internet Usage Policy. Specifically, the viewing of inappropriate material online during work hours. View Recorded Evidence. Contoso Corp HR Team.",
    "HR Disciplinary Notice: An investigation into employee device usage flagged serious policy infractions on your workstation. Review recorded evidence immediately to prevent immediate termination. Contoso Corp Human Resources.",
    "Internal Workplace Alert: Non-compliance detected regarding company device policy. Employee viewed prohibited content online during business hours. Download and view recorded evidence to submit your explanation.",
    "Notice from Human Resources: A violation of the Employee Code of Conduct has been logged against your corporate account. Kindly review the aforementioned evidence and acknowledge receipt within 24 hours.",
    "Compliance Investigation Notice: Unauthorized software and prohibited internet activity detected on your enterprise laptop. Click here to review security audit logs and recorded evidence.",
    "Workplace Policy Infraction: You have been reported for severe internet usage policy breach. Review recorded evidence and schedule mandatory disciplinary interview with HR management.",
    "Staff Alert: IT Security monitoring discovered inappropriate browsing history on your work terminal. View evidence report now or account will be suspended.",
    "Confidential HR Memo: Immediate action required regarding workplace harassment investigation involving your email account. Review case evidence securely.",

    # IT Support / Helpdesk / MFA / O365 Spear Phishing
    "IT Department: Your Microsoft 365 password expires in 2 hours. Keep your current password by verifying your credentials at the authentication portal.",
    "Global IT Helpdesk: Multi-Factor Authentication (MFA) sync required for all employee accounts. Click here to complete Duo/Okta re-authentication.",
    "Corporate Security Admin: Zscaler cloud security agent update failed on your device. Re-authenticate with your corporate SSO to prevent network lockout.",
    "Contoso IT Operations: Urgent VPN certificate renewal required. Log in to the secure gateway to update your enterprise credentials.",
    "System Administrator Alert: Unusual sign-in attempts detected on your enterprise mailbox. Verify identity immediately to unblock incoming mail flow.",
    "Microsoft Outlook Security: 7 incoming messages are on hold due to unverified SSL certificates. Release quarantined messages by verifying your email.",

    # Extortion & Blackmail
    "We have recorded your screen and webcam while you were visiting adult inappropriate websites. Send $1000 in Bitcoin or the recorded video will be emailed to your colleagues and family.",
    "Cyber Crime Unit Notice: Your device IP was tracked downloading copyrighted and illegal media. Pay administrative fine now to dismiss criminal warrant.",
    "Legal Subpoena: You are summoned as a defendant in copyright infringement case. Review recorded digital evidence attached to avoid arrest.",

    # Consumer Brands & Credential Harvesting
    "Google Notifications: Sign-in attempt was blocked. Someone just used your password to try to sign in to your account from a non-Google app. Check activity.",
    "Google Security Alert: Unauthorized login attempt from Russia. Review account activity to make sure no one else has access.",
    "PayPal Security: Your account has been temporarily restricted due to unusual activity. Confirm your billing information to restore full access.",
    "Apple Support: Your Apple ID was used to purchase an iPhone on an unrecognized device. If this was not you, cancel transaction immediately.",
    "Netflix Billing: Your payment method failed to renew your subscription. Update credit card details within 24 hours to avoid cancellation.",
    "Amazon Fraud Detection: Order #938-2819 placed for $899.99 PlayStation 5. Call fraud desk immediately or click link to cancel charge.",
    "Chase Online Banking: Security alert: Account locked following 3 failed password attempts. Unlock your account via one-time passkey.",
    "Bank of America Alert: Unusual wire transfer of $2,450 initiated to external beneficiary. Confirm or decline transaction.",

    # Delivery & Logistics Lures
    "USPS Delivery Notice: Package #9400111899562 could not be delivered due to missing house number. Update your delivery address to schedule redelivery.",
    "DHL Express: Shipment on hold at customs clearance facility. Pay $2.95 handling fee to release parcel for final delivery.",
    "FedEx Tracking: Your package is awaiting signature. Confirm contact details and track status at tinyurl.com/fedex-pkg.",

    # Financial / Payroll / Invoice Scams
    "Accounting Dept: Overdue invoice #INV-88392 attached. Remit payment to updated bank account details provided in invoice.",
    "Payroll Department: Your direct deposit account information was rejected. Submit updated routing number to ensure timely salary disbursement.",
    "Wire Transfer Confirmation: Please approve pending wire transfer of $45,000 for vendor services before bank cut-off time.",
    "Annual Compensation Statement: Your salary revision and bonus calculation for Q3 is ready for review. Access secure employee portal.",

    # Lottery & Prize Scams
    "Congratulations! You have been selected as the grand prize winner of $250,000 in the International Cash Lottery. Claim prize here.",
    "Walmart Survey Reward: Complete 30-second customer satisfaction survey and receive a $100 Amazon gift card immediately.",

    # Defanged & Obfuscated Phishing IOCs
    "Urgent security notice from webnotifications[.]net to john[.]doe@mybusiness[.]com regarding blocked sign-in attempt. Check activity now.",
    "Workplace Alert from workplace-alerts@webnotifications[.]net: View Recorded Evidence of device usage policy violation.",
    "hxxps://accounts[.]google-verification[.]com/signin?ref=urgent_security_alert"
]

BENIGN_TEMPLATES = [
    # Enterprise Workplace Communications (Legitimate)
    "Team, please find attached the meeting minutes from today's weekly sync. Let me know if any action items need adjustments before tomorrow.",
    "Sprint Planning Reminder: Sprint 24 starts on Monday at 10 AM. Please make sure all backlog tickets have story point estimates.",
    "Hi Sarah, thanks for reviewing the pull request. I have addressed your comments regarding the database query optimization.",
    "Contoso Corp Company Update: Congratulations to the product engineering team for reaching our Q3 milestone ahead of schedule!",
    "Device and Internet Usage Policy Annual Reminder: As part of our annual corporate compliance, please review the employee handbook on the intranet.",
    "IT Department Announcement: Scheduled network maintenance will take place this Saturday between 11 PM and 2 AM. All cloud services remain online.",
    "Lunch and Learn Session: Join us this Thursday in Conference Room B for an interactive presentation on container orchestration with Kubernetes.",
    "Quarterly All-Hands Meeting: Please submit your questions for the executive leadership Q&A through the internal company portal.",
    "HR Notice: Open enrollment for health insurance benefits begins next month. Detailed benefit guides are available on the corporate intranet.",
    "Performance Review Cycle: Mid-year self-evaluations are due by Friday end of day. Reach out to your direct manager with any questions.",
    "Project Status Update: The client has approved the design mockups for phase 2. We will begin frontend implementation next week.",
    "Happy Friday everyone! Just a reminder that the office will be closed next Monday in observance of the national holiday.",
    "Contoso Corp Social Committee: Sign up for the annual charity fun run taking place next month in downtown park.",

    # Legitimate Customer Service & System Emails
    "Your Google Cloud monthly billing statement is now ready. You can review your detailed usage breakdown in the Google Cloud Console.",
    "GitHub: Pull request #89 was successfully merged into master by developer. No build conflicts detected in automated pipeline.",
    "Your Amazon.com order #112-9849201 has shipped and is estimated to arrive by Thursday evening. Track package in your Amazon account.",
    "Calendar Invite: Weekly 1-on-1 Catchup with Team Lead on Wednesday at 2:00 PM in Room 402.",
    "Your monthly bank statement for the period ending September 30 is available to download in your secure mobile banking app.",
    "Zoom Video Communications: Meeting invitation for Architecture Review. Meeting ID: 829 104 291.",
    "Slack Notification: You have 3 unread messages in the #general and #announcements channels from your workspace team.",
    "DocuSign: The Master Services Agreement has been completed by all parties. A finalized copy has been saved to your account.",

    # Casual / Personal Correspondence
    "Hey John, hope you are doing well. Are you free to grab lunch tomorrow around 12:30 at the deli downstairs?",
    "Hi mom, arrived safely at the hotel. Weather is great here, will send some photos tomorrow morning!",
    "Thanks for recommending that book, I finished reading it yesterday and really enjoyed the insights on history.",
    "Hi everyone, here is the recipe for the chocolate cake I brought to the office yesterday as requested.",
    "Can you please send over the slide deck from yesterday's conference when you get a chance? Thanks!"
]

def augment_phishing_data():
    """Synthesizes high-variance phishing examples across multiple attack archetypes."""
    augmented = []
    
    # 1. Base templates
    augmented.extend(PHISHING_TEMPLATES)
    
    # 2. Permutations of Workplace HR & Disciplinary Spear Phishing
    pretexts = [
        "Workplace Alert", "Contoso Corp HR Team", "Corporate Security Notice",
        "Employee Relations", "Internal Affairs Unit", "IT Compliance Department",
        "Human Resources Directorate", "Workplace Conduct Committee"
    ]
    allegations = [
        "violation of our Device and Internet Usage Policy",
        "the viewing of inappropriate material online during work hours",
        "prohibited downloading of adult content on corporate equipment",
        "unauthorized personal streaming and bandwidth consumption",
        "severe breach of company workstation security guidelines",
        "confidentiality leak traced to your company-assigned laptop"
    ]
    ctas = [
        "View Recorded Evidence.", "Review Recorded Evidence.",
        "Download Evidence Report.", "Access Evidence File.",
        "Kindly review the aforementioned evidence and acknowledge.",
        "Examine screen recording logs.", "Inspect logged surveillance proof."
    ]
    senders = [
        "workplace-alerts@webnotifications[.]net", "hr-compliance@mail-delivery[.]net",
        "security-desk@company-alerts[.]net", "disciplinary-review@webnotifications[.]net",
        "noreply@staff-notifications[.]com", "hr-notice@internal-audit[.]net"
    ]
    
    for _ in range(80):
        p = random.choice(pretexts)
        a = random.choice(allegations)
        c = random.choice(ctas)
        s = random.choice(senders)
        text = f"{p} ( {s} ) to employee@mybusiness[.]com : We have identified recent activity on your company-assigned device that appears to be in {a}. {c} We believe this may be an oversight on your part. Best regards, The Contoso Corp HR Team."
        augmented.append(text)
        
    # 3. Permutations of IT Helpdesk & MFA Reset
    it_entities = ["Microsoft 365", "Okta Verify", "Duo Security", "Zscaler Cloud", "VPN Gateway", "Google Workspace", "Cisco AnyConnect"]
    it_reasons = ["password expires today", "MFA re-synchronization required", "security certificate expired", "unauthorized login from overseas", "session terminated by admin"]
    for _ in range(60):
        ent = random.choice(it_entities)
        rsn = random.choice(it_reasons)
        text = f"Urgent IT Security Alert: Your {ent} {rsn}. Keep your credentials active by validating your account identity immediately at our authentication portal. Failure to verify within 12 hours will lock your enterprise access."
        augmented.append(text)

    # 4. Permutations of Extortion & Webcam Blackmail
    for _ in range(50):
        text = f"Attention: I recorded a split-screen video of you watching inappropriate adult videos while recording your webcam on your device. I have exported your contacts list from your email. If you do not pay $950 in Bitcoin to my wallet within 48 hours, I will publish the video evidence to your employer and family."
        augmented.append(text)

    # 5. Financial Wire & Urgent Payment Lures
    vendors = ["Vendor Invoicing", "Accounts Payable", "Audit Billing", "SWIFT Wire Desk"]
    for _ in range(50):
        v = random.choice(vendors)
        text = f"URGENT: {v} - Outstanding invoice payment past due. Please review attached invoice and approve electronic funds transfer before 4:00 PM today to prevent commercial credit hold."
        augmented.append(text)

    # 6. Consumer Credential Scams
    brands = ["Google", "PayPal", "Apple", "Netflix", "Amazon", "Chase", "Wells Fargo", "Binance", "MetaMask"]
    actions = ["Sign-in attempt was blocked", "Someone used your password", "Account limited due to suspicious activity", "Payment method declined", "Wallet security compromised"]
    for _ in range(70):
        b = random.choice(brands)
        act = random.choice(actions)
        text = f"{b} Security Alert: {act}. We detected unusual access from an unknown device. Check activity immediately to verify your identity and secure your login credentials."
        augmented.append(text)

    # 7. SMS / Package Delivery Scams
    couriers = ["USPS", "FedEx", "DHL", "UPS"]
    for _ in range(50):
        c = random.choice(couriers)
        text = f"{c} Alert: Your package delivery is pending due to incomplete address details. Update your shipping address at bit.ly/track-pkg-{random.randint(100,999)} or parcel will be returned to sender."
        augmented.append(text)

    return augmented

def augment_benign_data():
    """Synthesizes high-variance legitimate workplace & personal communications."""
    augmented = []
    augmented.extend(BENIGN_TEMPLATES)

    # Permutations of workplace memos, projects, and meetings
    departments = ["Engineering", "Product Design", "Marketing", "Sales", "Customer Support", "Finance", "Legal", "Quality Assurance"]
    activities = [
        "weekly team standup", "sprint retrospective", "quarterly business review",
        "roadmap planning session", "code review discussion", "monthly budget review",
        "client feedback sync", "documentation update", "product release retrospective"
    ]
    times = ["Monday at 10 AM", "tomorrow afternoon", "this Wednesday at 2 PM", "Thursday morning", "next Tuesday at 11 AM"]

    for _ in range(120):
        d = random.choice(departments)
        act = random.choice(activities)
        t = random.choice(times)
        text = f"Hi {d} team, please find the agenda for our {act} scheduled for {t}. Let me know if you would like to add any discussion topics to the slide deck before our meeting."
        augmented.append(text)

    # Legitimate corporate policy reminders (Neutral, educational, no urgent links/threats)
    for _ in range(50):
        text = f"Annual Employee Handbook & Workplace Policy Reminder: Contoso Corp is committed to maintaining a professional, respectful, and secure work environment. Please review the Device and Internet Usage guidelines on our internal intranet wiki at your convenience. Thank you for your continued dedication."
        augmented.append(text)

    # Legitimate system & service notifications
    services = ["Google Cloud", "AWS", "GitHub", "Slack", "Jira", "Confluence", "Microsoft Teams", "GitLab"]
    for _ in range(80):
        srv = random.choice(services)
        text = f"Notification from {srv}: Your weekly digest is ready. 12 tasks were completed in your assigned sprint, and 4 pull requests are awaiting your review. Have a great week!"
        augmented.append(text)

    # Personal casual emails
    for _ in range(80):
        text = f"Hi there, hope your week is going smoothly! Let me know if you have time for a quick phone call this week to catch up on weekend plans. Cheers!"
        augmented.append(text)

    return augmented

def build_and_train_model():
    print("=" * 70)
    print("GILLNET AI: TRAINING GENERALIZED MULTI-VECTOR PHISHING NLP MODEL")
    print("=" * 70)

    phish_data = augment_phishing_data()
    benign_data = augment_benign_data()

    print(f"Loaded {len(phish_data)} Phishing/Spear-Phishing samples.")
    print(f"Loaded {len(benign_data)} Benign/Workplace Legitimate samples.")

    X = phish_data + benign_data
    y = [1] * len(phish_data) + [0] * len(benign_data)

    # Split into train/test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    print(f"Training set: {len(X_train)} samples | Test set: {len(X_test)} samples.")

    # Feature extraction with character & word n-grams
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 3),
        max_features=12000,
        sublinear_tf=True,
        token_pattern=r"(?u)\b\w+\b|\[\.\]|\[@\]"
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Train Calibrated Classifier Ensemble (Logistic Regression + Random Forest)
    clf_lr = LogisticRegression(C=3.0, max_iter=1000, class_weight="balanced", random_state=42)
    clf_rf = RandomForestClassifier(n_estimators=120, max_depth=25, random_state=42)

    ensemble = VotingClassifier(
        estimators=[('lr', clf_lr), ('rf', clf_rf)],
        voting='soft'
    )

    # 5-Fold Stratified Cross-Validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(ensemble, X_train_vec, y_train, cv=cv, scoring='accuracy')

    print(f"5-Fold Cross-Validation Accuracy: {cv_scores.mean() * 100:.2f}% (+/- {cv_scores.std() * 100:.2f}%)")

    # Fit ensemble
    ensemble.fit(X_train_vec, y_train)

    # Evaluate on holdout test set
    y_pred = ensemble.predict(X_test_vec)
    y_prob = ensemble.predict_proba(X_test_vec)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\nHOLDOUT TEST SET EVALUATION:")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN / HAM", "PHISHING / SCAM"]))

    # Model artifact package
    model_payload = {
        "model": ensemble,
        "vectorizer": vectorizer,
        "metrics": {
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1": round(f1 * 100, 2),
            "cv_mean": round(cv_scores.mean() * 100, 2)
        }
    }

    model_path = os.path.join(BASE_DIR, "email_phishing_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(model_payload, f)

    print(f"\nSuccessfully serialized generalized NLP phishing model to: {model_path}")

    # Test directly against the user's specific sample text
    test_user_sample = (
        "Workplace Alert ( workplace-alerts@webnotifications[.]net )\n"
        "to john[.]doe@mybusiness[.]com\n"
        "Dear John Doe,\n"
        "I hope this message finds you well.\n"
        "This email is to bring to your attention an issue of concern. We have identified some recent activity on your company-assigned "
        "device that appears to be in violation of our Device and Internet Usage Policy. Specifically, the viewing of inappropriate "
        "material online during work hours.\n"
        "View Recorded Evidence.\n"
        "This action contradicts our policy which explicitly prohibits such use. Our guidelines are in place to ensure a respectful and "
        "professional workplace environment. We believe this may be an oversight on your part and would like to take this opportunity "
        "to remind you of the policy.\n"
        "Kindly review the aforementioned evidence, and acknowledge your understanding and adherence to it by replying to this email.\n"
        "We value your contribution to our team and trust that this will be addressed promptly. Please feel free to reach out if you have "
        "any questions or concerns.\n"
        "Best regards,\n"
        "The Contoso Corp HR Team\n"
        "\"Empowering People, Driving Success\""
    )

    vec_sample = vectorizer.transform([test_user_sample])
    prob_sample = ensemble.predict_proba(vec_sample)[0, 1]
    pred_sample = ensemble.predict(vec_sample)[0]

    print("\n" + "=" * 70)
    print("VALIDATION ON USER'S EXACT ENTERPRISE SPEAR-PHISHING SAMPLE:")
    print(f"Prediction: {'PHISHING' if pred_sample == 1 else 'BENIGN'}")
    print(f"Phishing Probability: {prob_sample * 100:.2f}%")
    print("=" * 70)

if __name__ == "__main__":
    build_and_train_model()
