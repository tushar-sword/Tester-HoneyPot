export const SCENARIOS = [

/* 1 — Bank KYC Freeze */
{
  scenarioId: 'bank_kyc_freeze',
  name: 'SBI Suspicious Login',
  scamType: 'bank_fraud',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'Hi, this is Rohan from SBI Risk Monitoring. We detected a login attempt from Jaipur on your account ending 3456. Was this you?',

  metadata: { channel: 'SMS', language: 'English', locale: 'IN' },

  fakeData: {
    bankAccount: '3748291056473829',
    upiId: 'sbiverify.secure@okaxis',
    phoneNumber: '+91-9821034567',
    emailAddress: 'kyc.update@sbi-secure-portal.in'
  },

  followUps: [
    'If this wasn’t you, we need to secure the account immediately.',
    'Don’t worry, funds are safe for now.',
    'Can you confirm if you use UPI frequently?',
    'We are seeing multiple failed OTP attempts.',
    'To freeze suspicious access, send Re 1 to our backend verification ID sbiverify.secure@okaxis.',
    'This is only for authentication, not a debit.',
    'If you prefer speaking, call our direct fraud desk: 9821034567.',
    'We are marking account 3748291056473829 for temporary hold.',
    'Delay may result in full debit block.',
    'You may also email your updated KYC copy to kyc.update@sbi-secure-portal.in.',
    'Our system will auto-escalate in 20 minutes.',
    'I am trying to help you avoid permanent freeze.',
    'Please confirm once done.',
    'Last reminder before we escalate this to permanent block.'
 ]
},

/* 2 — Job Scam */
{
  scenarioId: 'wfh_data_entry',
  name: 'WFH Data Entry Role',
  scamType: 'job_scam',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'Hello Shambhavi, we shortlisted your profile for a remote Data Entry Executive role. ₹45,000/month. Flexible hours. Interested?',

  metadata: { channel: 'WhatsApp', language: 'English', locale: 'IN' },

  fakeData: {
    bankAccount: '9988776655443322',
    upiId: 'hr.registration@quickpay',
    phoneNumber: '+91-7788991234',
    emailAddress: 'hr.operations@career-fasttrack.com'
  },

  followUps: [
    'Great. Just a basic screening process.',
    'No heavy interview, just document verification.',
    'Work is simple data compilation.',
    'We require a refundable onboarding fee.',
    'This ensures serious applicants only.',
    'You can pay ₹999 to hr.registration@quickpay.',
    'Or transfer to salary processing account 9988776655443322.',
    'Call 7788991234 once payment is done so we lock your slot.',
    'Send payment proof to hr.operations@career-fasttrack.com.',
    'Your batch starts tomorrow.',
    'Delay may move you to next cycle.',
    'Three candidates already confirmed.',
    'We cannot hold the position without fee.',
    'Confirm once payment completed.'
  ]
},

/* 3 — Crypto Investment */
{
  scenarioId: 'crypto_investment',
  name: 'CryptoPro Insider Returns',
  scamType: 'crypto_investment',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'Hey, random question. Have you explored crypto trading? I’ve been getting insane returns lately.',

  metadata: { channel: 'Telegram', language: 'English', locale: 'IN' },

  fakeData: {
    bankAccount: '8374019283746501',
    upiId: 'cryptopro.deposit@ibl',
    phoneNumber: '+91-9902837465',
    phishingLink: 'http://cryptopro-india-trade.com/register?ref=2025'
  },

  followUps: [
    'It’s not public yet. Early access platform.',
    'My mentor works with regulatory insiders.',
    'Limited investor pool.',
    'You can check it here: http://cryptopro-india-trade.com/register?ref=2025',
    'Minimum deposit ₹10,000.',
    'Most members start with ₹25,000.',
    'UPI works. Use cryptopro.deposit@ibl.',
    'If bank transfer easier, use 8374019283746501.',
    'Support team at 9902837465 can guide you.',
    'Returns start next trading cycle.',
    'Last batch saw 18% in 5 days.',
    'Withdrawals processed instantly.',
    'Seats closing tonight.',
    'Don’t miss early access window.'
  ]
},

/* 4 — Electricity Disconnection */
{
  scenarioId: 'electricity_disconnect',
  name: 'Electricity Disconnection Alert',
  scamType: 'utility_scam',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'Electricity Dept: Your meter flagged for unpaid dues. Disconnection scheduled tonight 9:30 PM.',

  metadata: { channel: 'SMS', language: 'English', locale: 'IN' },

  fakeData: {
    bankAccount: '1122334455667788',
    upiId: 'powerbill.support@ibl',
    phoneNumber: '+91-8877665544',
    emailAddress: 'billing@power-dept-resolution.com'
  },

  followUps: [
    'This is officer Mishra speaking.',
    'Outstanding ₹3,240 including reconnection fee.',
    'Your meter ID flagged under audit.',
    'Disconnection truck already assigned.',
    'You can clear via UPI powerbill.support@ibl.',
    'Or transfer to 1122334455667788.',
    'Call 8877665544 after payment confirmation.',
    'Send receipt to billing@power-dept-resolution.com.',
    'We can delay cutoff for 30 minutes.',
    'After that system auto-updates.',
    'Reconnection takes 24 hours.',
    'Penalty may increase tomorrow.',
    'I suggest resolving immediately.',
    'Confirm once paid.'
  ]
},

/* 5 — Income Tax Refund */
{
  scenarioId: 'tax_refund',
  name: 'Income Tax Refund Pending',
  scamType: 'refund_scam',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'Income Tax Dept: Refund of ₹19,840 pending. Bank details need verification.',

  metadata: { channel: 'SMS', language: 'English', locale: 'IN' },

  fakeData: {
    bankAccount: '3746501928374650',
    upiId: 'refund.process@itdpay',
    phoneNumber: '+91-7788553311',
    emailAddress: 'refund@incometax-portal-help.org'
  },

  followUps: [
    'Officer Kapoor here from Refund Cell.',
    'Refund amount ₹19,840 confirmed.',
    'Small ₹250 portal validation required.',
    'This activates refund gateway.',
    'Pay via refund.process@itdpay.',
    'Or confirm account 3746501928374650.',
    'Call 7788553311 if portal not opening.',
    'Send PAN copy to refund@incometax-portal-help.org.',
    'Delay may shift refund to next quarter.',
    'System expires in 15 minutes.',
    'Verification pending from your side.',
    'Refund cannot process without validation.',
    'Please confirm once completed.',
    'Final reminder before refund cancellation.'
  ]
},

/* 6 — Amazon Over-refund */
{
  scenarioId: 'amazon_overrefund',
  name: 'Amazon Excess Refund Recovery',
  scamType: 'refund_scam',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'Amazon Finance: We mistakenly refunded ₹7,500 instead of ₹299. Need assistance resolving this.',

  metadata: { channel: 'Phone', language: 'English', locale: 'IN' },

  fakeData: {
    bankAccount: '9182736450918273',
    upiId: 'amazon.returns@axispay',
    phoneNumber: '+91-9900112233',
    emailAddress: 'refund-ops@amazon-support-india.org'
  },

  followUps: [
    'This avoids fraud flag on your account.',
    'Please return ₹7,201.',
    'Otherwise account may suspend.',
    'UPI: amazon.returns@axispay.',
    'Or bank transfer 9182736450918273.',
    'Call 9900112233 once done.',
    'Share screenshot at refund-ops@amazon-support-india.org.',
    'This is system-generated correction.',
    'We are helping avoid legal escalation.',
    'Refund error occurred at warehouse.',
    'Finance audit closing today.',
    'Delay may block your Amazon wallet.',
    'Confirm once transfer complete.',
    'Case auto-closes in 10 minutes.'
  ]
},

/* 7 — Loan Approval */
{
  scenarioId: 'instant_loan',
  name: 'Pre-approved Personal Loan',
  scamType: 'loan_scam',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'You are pre-approved for ₹4,00,000 loan at 8.5%. No CIBIL check. Interested?',

  metadata: { channel: 'WhatsApp', language: 'English', locale: 'IN' },

  fakeData: {
    bankAccount: '7465019283746501',
    upiId: 'loanapproval.nbfc@ibl',
    phoneNumber: '+91-6655443322',
    emailAddress: 'loans@instantcredit-nbfc.com'
  },

 followUps: [
    'Only processing + insurance fee required.',
    '₹3,500 refundable.',
    'Approval already pre-verified.',
    'Funds disbursed within 30 minutes.',
    'Pay to loanapproval.nbfc@ibl.',
    'Or account 7465019283746501.',
    'Call 6655443322 to lock approval.',
    'Agreement sent from loans@instantcredit-nbfc.com.',
    'Interest fixed at 8.5%.',
    'Offer expires today.',
    'Many applicants waiting.',
    'Without fee, file cannot move.',
    'Kindly confirm once paid.',
    'Final reminder before approval lapse.'
  ]
},

/* 8 — Tech Support */
{
  scenarioId: 'windows_virus',
  name: 'Microsoft Virus Alert',
  scamType: 'tech_support',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'Your Windows system is sending critical virus alerts. Immediate action required to prevent data loss.',

  metadata: { channel: 'Popup', language: 'English', locale: 'IN' },

  fakeData: {
    bankAccount: '5019283746501928',
    upiId: 'microsoft.support@techpay',
    phoneNumber: '+91-7766554433',
    emailAddress: 'support@microsoft-helpdesk-india.com'
  },

  followUps: [
    'I’m Alex from Microsoft Security.',
    'We detected 47 Trojan files.',
    'System may crash anytime.',
    'Advanced removal ₹2,499.',
    'Pay to microsoft.support@techpay.',
    'Or bank transfer 5019283746501928.',
    'Call 7766554433 for remote assistance.',
    'Email license key to support@microsoft-helpdesk-india.com.',
    'We need immediate remote access.',
    'Otherwise files may corrupt.',
    'This is critical security alert.',
    'Delay increases damage.',
    'Confirm once payment done.',
    'Session closing soon.'
  ]
},

/* 9 — Delivery Phishing */
{
  scenarioId: 'delivery_reschedule',
  name: 'Package Delivery Issue',
  scamType: 'phishing_link',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'Your package could not be delivered due to address issue. Please confirm details.',

  metadata: { channel: 'Email', language: 'English', locale: 'IN' },

  fakeData: {
    upiId: 'delivery.fee@ibl',
    phoneNumber: '+91-7042198653',
    phishingLink: 'http://parcel-redelivery-update.com/track?id=28374',
    emailAddress: 'delivery.support@parcel-update-center.net'
  },

  followUps: [
    'Address incomplete in shipment record.',
    'Update here: http://parcel-redelivery-update.com/track?id=28374',
    '₹49 re-delivery charge.',
    'Pay to delivery.fee@ibl.',
    'Call 7042198653 if link not loading.',
    'Send confirmation to delivery.support@parcel-update-center.net.',
    'Package held at local hub.',
    'Failure to update returns parcel.',
    'Re-attempt within 12 hours.',
    'Tracking ID 28374 flagged.',
    'Courier awaiting confirmation.',
    'Delay may cancel shipment.',
    'Kindly complete update now.',
    'Final reminder before return to sender.'
  ]
},

/* 10 — UPI Reward */
{
  scenarioId: 'upi_loyalty_reward',
  name: 'UPI Loyalty Cashback',
  scamType: 'upi_scam',
  weight: 10,
  maxTurns: 15,
  initialMessage:
    'Congratulations. Your UPI ID selected for ₹12,000 loyalty reward under Digital Program.',

  metadata: { channel: 'SMS', language: 'English', locale: 'IN' },

  fakeData: {
    bankAccount: '6291847503918274',
    upiId: 'reward.claim@ibl',
    phoneNumber: '+91-8130045672',
    phishingLink: 'http://upi-reward-digital-claim.com/verify'
  },

 followUps: [
    'Verification required before transfer.',
    'Visit http://upi-reward-digital-claim.com/verify to activate reward.',
    'Send Re 1 to reward.claim@ibl for authentication.',
    'If UPI fails, confirm bank account 6291847503918274.',
    'Call 8130045672 for quick assistance with verification.',
    'Reward valid today only.',
    'Selected under festive cashback drive.',
    'Delay cancels eligibility.',
    'Processing takes 2 minutes.',
    'UPI authentication mandatory.',
    'System auto-expires tonight.',
    'Limited beneficiaries.',
    'Confirm once verification done.',
    'Last reminder before reward forfeited.'
  ]
}

];

/**
 * Maps fakeData keys to extractedIntelligence array keys in the payload.
 */
export const FAKE_DATA_KEY_MAP = {
  bankAccount:  'bankAccounts',
  upiId:        'upiIds',
  phoneNumber:  'phoneNumbers',
  phishingLink: 'phishingLinks',
  emailAddress: 'emailAddresses',
};