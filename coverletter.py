import os
import json
import uuid
import anthropic
import resend
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_file
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT
import secrets

app = Flask(__name__)

JOBS_FILE = '/var/log/coverletter-jobs.json'
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
RESEND_API_KEY = os.getenv('RESEND_API_KEY')

anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
resend.api_key = RESEND_API_KEY

def load_jobs():
    if os.path.exists(JOBS_FILE):
        with open(JOBS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_jobs(jobs):
    with open(JOBS_FILE, 'w') as f:
        json.dump(jobs, f, indent=2)

def generate_access_code():
    return secrets.token_urlsafe(16)

@app.route('/api/coverletter/create', methods=['POST'])
def create_cover_letter():
    data = request.json
    job_posting = data.get('job_posting', '').strip()
    your_name = data.get('your_name', '').strip()
    your_background = data.get('your_background', '').strip()
    email = data.get('email', '').strip()
    
    if not all([job_posting, your_name, your_background, email]):
        return jsonify({'error': 'All fields required'}), 400
    
    job_id = str(uuid.uuid4())
    access_code = generate_access_code()
    timestamp = datetime.now().isoformat()
    
    job = {
        'id': job_id,
        'type': 'cover_letter',
        'job_posting': job_posting,
        'your_name': your_name,
        'your_background': your_background,
        'email': email,
        'access_code': access_code,
        'status': 'pending',
        'created_at': timestamp,
        'delete_at': (datetime.now() + timedelta(hours=2)).isoformat(),
        'extended': False
    }
    
    jobs = load_jobs()
    jobs[job_id] = job
    save_jobs(jobs)
    
    return jsonify({
        'job_id': job_id,
        'checkout_url': f'https://buy.stripe.com/28o28q6RCcm17Fu149?client_reference_id={job_id}&success_url=https://coverletter.harborprivacy.com/processing?job_id={job_id}&prefilled_email={email}'
    })

@app.route('/api/resume/create', methods=['POST'])
def create_resume_review():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
    except Exception as e:
        return jsonify({'error': 'Invalid JSON data'}), 400
    
    resume_text = data.get('resume_text', '').strip()
    email = data.get('email', '').strip()
    
    if not resume_text or not email:
        return jsonify({'error': 'Resume text and email required'}), 400
    
    if len(resume_text) > 50000:
        return jsonify({'error': 'Resume too long (max 50k chars)'}), 400
    
    job_id = str(uuid.uuid4())
    access_code = generate_access_code()
    timestamp = datetime.now().isoformat()
    
    job = {
        'id': job_id,
        'type': 'resume_review',
        'email': email,
        'resume_text': resume_text,
        'access_code': access_code,
        'status': 'pending',
        'created_at': timestamp,
        'delete_at': (datetime.now() + timedelta(hours=2)).isoformat(),
        'extended': False
    }
    
    jobs = load_jobs()
    jobs[job_id] = job
    save_jobs(jobs)
    
    return jsonify({
        'job_id': job_id,
        'checkout_url': f'https://buy.stripe.com/00w5kCdMP4Pl4njbd56kg0i?client_reference_id={job_id}&success_url=https://resume.harborprivacy.com/processing?job_id={job_id}&prefilled_email={email}'
    })

@app.route('/api/coverletter/generate/<job_id>', methods=['POST'])
def generate_cover_letter(job_id):
    jobs = load_jobs()
    job = jobs.get(job_id)
    
    if not job or job.get('type') != 'cover_letter':
        return jsonify({'error': 'Job not found'}), 404
    
    if job['status'] != 'paid':
        return jsonify({'error': 'Payment required'}), 402
    
    if job['status'] == 'completed':
        return jsonify({'error': 'Already generated'}), 400
    
    job['status'] = 'generating'
    save_jobs(jobs)
    
    prompt = f"""Write a professional cover letter for this job posting.

Job Posting:
{job['job_posting']}

Candidate Name: {job['your_name']}

Candidate Background:
{job['your_background']}

Write a compelling cover letter that highlights relevant experience and shows genuine interest. Keep it under 400 words. Do not include address blocks or date. Start with "Dear Hiring Manager," and end with "Sincerely,". Do not include the candidate's name at the end."""

    try:
        response = anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        letter_text = response.content[0].text
        
        pdf_path = f'/tmp/coverletter_{job_id}.pdf'
        generate_pdf(letter_text, job['your_name'], pdf_path)
        
        job['status'] = 'completed'
        job['letter_text'] = letter_text
        job['pdf_path'] = pdf_path
        job['completed_at'] = datetime.now().isoformat()
        save_jobs(jobs)
        
        send_cover_letter_email(job)
        
        return jsonify({'status': 'completed'})
        
    except Exception as e:
        job['status'] = 'failed'
        job['error'] = str(e)
        save_jobs(jobs)
        return jsonify({'error': str(e)}), 500

@app.route('/api/resume/generate/<job_id>', methods=['POST'])
def generate_resume_review(job_id):
    jobs = load_jobs()
    job = jobs.get(job_id)
    
    if not job or job.get('type') != 'resume_review':
        return jsonify({'error': 'Job not found'}), 404
    
    if job['status'] != 'paid':
        return jsonify({'error': 'Payment required'}), 402
    
    if job['status'] == 'completed':
        return jsonify({'error': 'Already generated'}), 400
    
    job['status'] = 'generating'
    save_jobs(jobs)
    
    prompt = f"""You are a professional resume reviewer and career coach. Review this resume and provide specific, actionable feedback.

Resume:
{job['resume_text']}

Provide feedback in these areas:
1. ATS Optimization - specific keywords missing, formatting issues that break ATS parsing
2. Weak Language - vague phrases, passive voice, lack of metrics or impact statements
3. Experience Gaps - unexplained time gaps, missing relevant details, inconsistent formatting
4. Structure Issues - poor layout, missing sections, bad organization
5. Quick Wins - 3-5 immediate changes that would improve this resume

Be direct and specific. Use examples from their actual resume. No fluff."""

    try:
        response = anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        feedback = response.content[0].text
        
        job['status'] = 'completed'
        job['feedback'] = feedback
        job['completed_at'] = datetime.now().isoformat()
        save_jobs(jobs)
        
        send_resume_review_email(job)
        
        return jsonify({'status': 'completed'})
        
    except Exception as e:
        job['status'] = 'failed'
        job['error'] = str(e)
        save_jobs(jobs)
        return jsonify({'error': str(e)}), 500

@app.route('/api/job/status/<access_code>', methods=['GET'])
def get_job_status(access_code):
    jobs = load_jobs()
    
    job = None
    for j in jobs.values():
        if j.get('access_code') == access_code:
            job = j
            break
    
    if not job:
        return jsonify({'error': 'Invalid access code'}), 404
    
    delete_at = datetime.fromisoformat(job['delete_at'])
    now = datetime.now()
    time_remaining = int((delete_at - now).total_seconds())
    
    return jsonify({
        'status': job['status'],
        'type': job['type'],
        'time_remaining': max(0, time_remaining),
        'extended': job.get('extended', False),
        'your_name': job.get('your_name', ''),
        'letter_text': job.get('letter_text', ''),
        'feedback': job.get('feedback', '')
    })

@app.route('/api/job/extend/<access_code>', methods=['POST'])
def extend_job_access(access_code):
    jobs = load_jobs()
    
    job = None
    job_id = None
    for jid, j in jobs.items():
        if j.get('access_code') == access_code:
            job = j
            job_id = jid
            break
    
    if not job:
        return jsonify({'error': 'Invalid access code'}), 404
    
    if job.get('extended'):
        return jsonify({'error': 'Already extended'}), 400
    
    if job['type'] == 'cover_letter':
        checkout_url = f'https://buy.stripe.com/7sY00idMP6Xt7zv0yr6kg0j?client_reference_id={job_id}_extend'
    else:
        checkout_url = f'https://buy.stripe.com/cNiaEWdMPbdJ6vrbd56kg0k?client_reference_id={job_id}_extend'
    
    return jsonify({
        'job_id': job_id,
        'checkout_url': checkout_url
    })

@app.route('/api/job/update-header/<access_code>', methods=['POST'])
def update_header(access_code):
    data = request.json
    new_name = data.get('name', '').strip()
    phone = data.get('phone', '').strip()
    email = data.get('email', '').strip()
    
    jobs = load_jobs()
    
    job = None
    for j in jobs.values():
        if j.get('access_code') == access_code:
            job = j
            break
    
    if not job or job.get('type') != 'cover_letter':
        return jsonify({'error': 'Invalid access code'}), 404
    
    if new_name:
        job['your_name'] = new_name
    if phone:
        job['phone'] = phone
    if email:
        job['header_email'] = email
    
    pdf_path = f'/tmp/coverletter_{job["id"]}.pdf'
    generate_pdf(job['letter_text'], job['your_name'], pdf_path, phone, email)
    job['pdf_path'] = pdf_path
    
    save_jobs(jobs)
    
    return jsonify({'status': 'updated'})

@app.route('/api/coverletter/download/<access_code>', methods=['GET'])
def download_cover_letter(access_code):
    jobs = load_jobs()
    
    job = None
    for j in jobs.values():
        if j.get('access_code') == access_code and j.get('type') == 'cover_letter':
            job = j
            break
    
    if not job or job['status'] != 'completed':
        return jsonify({'error': 'Not found'}), 404
    
    return send_file(job['pdf_path'], as_attachment=True, download_name='cover_letter.pdf')

@app.route('/webhook/stripe', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        import stripe
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
        event = stripe.Webhook.construct_event(payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET'))
        
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            client_ref = session.get('client_reference_id', '')
            
            if '_extend' in client_ref:
                job_id = client_ref.replace('_extend', '')
                jobs = load_jobs()
                if job_id in jobs:
                    jobs[job_id]['extended'] = True
                    jobs[job_id]['delete_at'] = (datetime.now() + timedelta(hours=26)).isoformat()
                    save_jobs(jobs)
            else:
                jobs = load_jobs()
                if client_ref in jobs:
                    jobs[client_ref]['status'] = 'paid'
                    save_jobs(jobs)
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

def generate_pdf(letter_text, name, output_path, phone=None, email=None):
    doc = SimpleDocTemplate(output_path, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
    story = []
    styles = getSampleStyleSheet()
    
    header_style = ParagraphStyle(
        'Header',
        parent=styles['Normal'],
        fontSize=11,
        alignment=TA_LEFT,
        spaceAfter=6
    )
    
    story.append(Paragraph(f"<b>{name}</b>", header_style))
    if phone:
        story.append(Paragraph(phone, header_style))
    if email:
        story.append(Paragraph(email, header_style))
    
    story.append(Spacer(1, 0.3*inch))
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=11,
        leading=14,
        alignment=TA_LEFT,
        spaceAfter=12
    )
    
    paragraphs = letter_text.split('\n\n')
    for para in paragraphs:
        if para.strip():
            story.append(Paragraph(para.strip(), body_style))
    
    doc.build(story)

def send_cover_letter_email(job):
    access_url = f"https://coverletter.harborprivacy.com/success?code={job['access_code']}"
    
    html_content = f"""
    <h2>Your Cover Letter is Ready</h2>
    <p>Your AI-generated cover letter is attached to this email as a PDF.</p>
    <p><strong>Access your cover letter online:</strong><br>
    <a href="{access_url}">{access_url}</a></p>
    <p>You can update the header (add phone/email) or regenerate your letter at this link.</p>
    <p style="margin-top: 30px; color: #666; font-size: 12px;">Your data will be deleted 2 hours after payment. You can extend access for 24 hours for an additional $0.99.</p>
    """
    
    try:
        with open(job['pdf_path'], 'rb') as f:
            pdf_content = f.read()
        
        resend.Emails.send({
            "from": "Harbor Privacy Cover Letters <coverletter@mail.harborprivacy.com>",
            "to": [job['email']],
            "subject": "Your Cover Letter from Harbor Privacy",
            "html": html_content,
            "attachments": [{
                "filename": "cover_letter.pdf",
                "content": list(pdf_content)
            }]
        })
    except Exception as e:
        print(f"Email send failed: {e}")

def send_resume_review_email(job):
    access_url = f"https://resume.harborprivacy.com/success?code={job['access_code']}"
    
    html_content = f"""
    <h2>Your Resume Review</h2>
    <p>Here's your AI-generated resume feedback.</p>
    <p><strong>View your review online:</strong><br>
    <a href="{access_url}">{access_url}</a></p>
    <div style="background: #f5f5f5; padding: 20px; border-left: 4px solid #2563eb; white-space: pre-wrap; font-family: monospace; margin: 20px 0;">
{job['feedback']}
    </div>
    <p style="margin-top: 30px; color: #666; font-size: 12px;">Your data will be deleted 2 hours after payment. You can extend access for 24 hours for an additional $0.99.</p>
    """
    
    try:
        resend.Emails.send({
            "from": "Harbor Privacy Resume Review <resume@mail.harborprivacy.com>",
            "to": [job['email']],
            "subject": "Your Resume Review from Harbor Privacy",
            "html": html_content
        })
    except Exception as e:
        print(f"Email send failed: {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7100, debug=False)
