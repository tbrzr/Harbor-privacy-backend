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
    return str(secrets.randbelow(900000) + 100000)

@app.route('/api/coverletter/create', methods=['POST'])
def create_cover_letter():
    data = request.json
    job_posting = data.get('job_posting', '').strip()
    your_name = data.get('your_name', '').strip()
    your_background = data.get('your_background', '').strip()
    email = data.get('email', '').strip()
    tone = data.get('tone', 'professional').strip()
    length = data.get('length', 'standard').strip()
    
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
        'tone': tone,
        'length': length,
        'access_code': access_code,
        'status': 'pending',
        'created_at': timestamp,
        'delete_at': (datetime.now() + timedelta(hours=2)).isoformat(),
        'extended': False,
        'adjustments': [],
        'adjustment_count': 0
    }
    
    jobs = load_jobs()
    jobs[job_id] = job
    save_jobs(jobs)
    
    return jsonify({
        'job_id': job_id,
        'checkout_url': f'https://buy.stripe.com/bJe7sKfUXchNaLHa916kg0n?client_reference_id={job_id}&success_url=https://career.harborprivacy.com/processing?job_id={job_id}&prefilled_email={email}'
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
        'checkout_url': f'https://buy.stripe.com/7sYaEW103dlRf1X6WP6kg0m?client_reference_id={job_id}&success_url=https://resume.harborprivacy.com/processing?job_id={job_id}&prefilled_email={email}'
    })

@app.route('/api/coverletter/generate/<job_id>', methods=['POST'])
def generate_cover_letter(job_id):
    jobs = load_jobs()
    job = jobs.get(job_id)
    
    if not job:
        print(f"Job {job_id} not found in jobs file")
        return jsonify({'error': 'Job not found', 'job_id': job_id}), 404
    
    if job.get('type') != 'cover_letter':
        print(f"Job {job_id} is type {job.get('type')}, not cover_letter")
        return jsonify({'error': 'Job not found'}), 404
    
    if job['status'] != 'paid':
        return jsonify({'error': 'Payment required'}), 402
    
    if job['status'] == 'completed':
        return jsonify({'error': 'Already generated'}), 400
    
    job['status'] = 'generating'
    save_jobs(jobs)
    
    tone = job.get('tone', 'professional')
    length = job.get('length', 'standard')
    
    tone_instructions = {
        'professional': 'Write in a polished, professional tone. Formal but not stiff. Confident and clear.',
        'confident': 'Write in a bold, direct tone. Lead with impact. Cut filler. Every sentence earns its place.',
        'creative': 'Write in a creative, memorable tone. Open with something unexpected that grabs attention. Show personality while staying relevant. Make the hiring manager actually want to keep reading.',
        'conversational': 'Write in a warm, conversational tone. Sound like a real person, not a template. Approachable and genuine.'
    }.get(tone, 'Write in a polished, professional tone.')
    
    word_targets = {
        'concise': 'Keep it under 250 words.',
        'standard': 'Keep it under 350 words.',
        'detailed': 'Keep it under 450 words.'
    }.get(length, 'Keep it under 350 words.')
    
    prompt = f"""Write a cover letter for this job posting.

Job Posting:
{job['job_posting']}

Candidate Name: {job['your_name']}

Candidate Background:
{job['your_background']}

Tone: {tone_instructions}
Length: {word_targets}

Do not include address blocks or date. Start with "Dear Hiring Manager," and end with "Sincerely," followed by the candidate's full name on the next line. Do not use em dashes."""

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

def generate_resume_pdf(text, output_path):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.lib import colors
    import re

    NAVY = colors.HexColor('#1a3a5c')
    BLACK = colors.HexColor('#111111')
    GRAY = colors.HexColor('#555555')

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.45*inch, bottomMargin=0.45*inch,
        leftMargin=0.55*inch, rightMargin=0.55*inch
    )

    name_style = ParagraphStyle('name', fontName='Helvetica-Bold', fontSize=16, leading=18, textColor=NAVY, alignment=TA_CENTER, spaceAfter=2)
    contact_style = ParagraphStyle('contact', fontName='Helvetica', fontSize=8.5, leading=11, textColor=GRAY, alignment=TA_CENTER, spaceAfter=4)
    section_style = ParagraphStyle('section', fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=NAVY, spaceBefore=5, spaceAfter=2, letterSpacing=1.5)
    job_title_style = ParagraphStyle('jobtitle', fontName='Helvetica-Bold', fontSize=9, leading=11, textColor=BLACK, spaceAfter=0)
    job_sub_style = ParagraphStyle('jobsub', fontName='Helvetica-Oblique', fontSize=8.5, leading=10, textColor=GRAY, spaceAfter=1)
    bullet_style = ParagraphStyle('bullet', fontName='Helvetica', fontSize=8.5, leading=11, textColor=BLACK, leftIndent=10, firstLineIndent=-8, spaceAfter=1)
    body_style = ParagraphStyle('body', fontName='Helvetica', fontSize=8.5, leading=11, textColor=BLACK, spaceAfter=1)
    date_style = ParagraphStyle('date', fontName='Helvetica', fontSize=8.5, leading=11, textColor=GRAY, alignment=TA_RIGHT)

    def esc(t):
        return t.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')

    def hr():
        return HRFlowable(width='100%', thickness=0.75, color=NAVY, spaceAfter=3, spaceBefore=1)

    lines = text.split('\n')
    story = []
    first_line = True

    for line in lines:
        line = line.strip()

        if not line:
            story.append(Spacer(1, 2))
            continue

        if first_line:
            story.append(Paragraph(esc(line), name_style))
            story.append(hr())
            first_line = False
            continue

        if '|' in line and any(c.isdigit() for c in line) and '@' in line or ('|' in line and len(story) < 4):
            story.append(Paragraph(esc(line), contact_style))
            story.append(hr())
            continue

        if line.isupper() and len(line) < 60 and not line.startswith('•'):
            story.append(Spacer(1, 3))
            story.append(Paragraph(esc(line), section_style))
            story.append(hr())
            continue

        if line.startswith('•') or line.startswith('-'):
            clean = line.lstrip('•- ').strip()
            story.append(Paragraph(f'• {esc(clean)}', bullet_style))
            continue

        if re.search(r'(19|20)\d\d', line) and not line.startswith('•'):
            parts = re.split(r'\s{3,}|\t', line)
            if len(parts) >= 2:
                date_part = parts[-1].strip()
                title_part = ' '.join(parts[:-1]).strip()
                tbl = Table(
                    [[Paragraph(esc(title_part), job_title_style), Paragraph(esc(date_part), date_style)]],
                    colWidths=[4.5*inch, 2.3*inch]
                )
                tbl.setStyle(TableStyle([
                    ('VALIGN',(0,0),(-1,-1),'TOP'),
                    ('LEFTPADDING',(0,0),(-1,-1),0),
                    ('RIGHTPADDING',(0,0),(-1,-1),0),
                    ('TOPPADDING',(0,0),(-1,-1),1),
                    ('BOTTOMPADDING',(0,0),(-1,-1),0),
                ]))
                story.append(tbl)
            else:
                story.append(Paragraph(esc(line), job_title_style))
            continue

        if '|' in line:
            story.append(Paragraph(esc(line), job_sub_style))
            continue

        story.append(Paragraph(esc(line), body_style))

    doc.build(story)

def download_revised_resume(access_code):
    jobs = load_jobs()
    for job_id, job in jobs.items():
        if job.get('access_code') == access_code and job.get('type') == 'resume_review':
            expires = job.get('code_expires_at')
            if expires and datetime.fromisoformat(expires) < datetime.now():
                return jsonify({'error': 'Access code expired'}), 403
            if job.get('revised_pdf_path') and os.path.exists(job['revised_pdf_path']):
                return send_file(job['revised_pdf_path'], as_attachment=True, download_name='revised_resume.pdf')
            return jsonify({'error': 'PDF not ready'}), 404
    return jsonify({'error': 'Invalid code'}), 404


@app.route('/api/resume/download/<access_code>', methods=['GET'])
def download_revised_resume(access_code):
    jobs = load_jobs()
    for job_id, job in jobs.items():
        if job.get('access_code') == access_code and job.get('type') == 'resume_review':
            if job.get('revised_pdf_path') and os.path.exists(job['revised_pdf_path']):
                return send_file(job['revised_pdf_path'], as_attachment=True, download_name='revised_resume.pdf')
            return jsonify({'error': 'PDF not ready'}), 404
    return jsonify({'error': 'Invalid code'}), 404


@app.route('/api/job/status/check/<job_id>', methods=['GET'])
def check_job_status(job_id):
    jobs = load_jobs()
    job = jobs.get(job_id)
    if not job:
        return jsonify({'status': 'not_found'}), 404
    return jsonify({'status': job.get('status', 'pending')}), 200

@app.route('/api/resume/generate/<job_id>', methods=['POST'])
def generate_resume_review(job_id):
    jobs = load_jobs()
    job = jobs.get(job_id)
    
    if not job:
        print(f"Job {job_id} not found in jobs file")
        return jsonify({'error': 'Job not found', 'job_id': job_id}), 404
    
    if job.get('type') != 'resume_review':
        print(f"Job {job_id} is type {job.get('type')}, not resume_review")
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
        
        # Generate revised resume PDF
        try:
            resume_prompt = f"""Rewrite this resume to be stronger, more ATS-friendly, and more impactful. Apply the feedback you just gave. Keep all real facts, dates, and companies exactly the same. Only improve the language, structure, and formatting.

Original Resume:
{job['resume_text']}

Keep the professional summary to 2-3 sentences maximum. Keep bullets to one concise line each. Preserve ALL contact info exactly as written including phone, email, LinkedIn, and location. Return ONLY the improved resume text, no commentary, no markdown fences, no extra blank lines."""
            
            resume_response = anthropic_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=3000,
                messages=[{"role": "user", "content": resume_prompt}]
            )
            revised_text = resume_response.content[0].text
            
            # Generate PDF of revised resume
            pdf_path = f"/var/www/resume/pdfs/{job_id}_revised.pdf"
            os.makedirs("/var/www/resume/pdfs", exist_ok=True)
            generate_resume_pdf(revised_text, pdf_path)
            job['revised_pdf_path'] = pdf_path
            save_jobs(jobs)
        except Exception as pdf_err:
            import traceback
            print(f"Revised resume PDF failed: {pdf_err}")
            traceback.print_exc()

        job['resume_text'] = ''
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
        'feedback': job.get('feedback', ''),
        'has_pdf': bool(job.get('revised_pdf_path'))
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
        checkout_url = f'https://buy.stripe.com/7sY00idMP6Xt7zv0yr6kg0j?client_reference_id={job_id}_extend&success_url=https://career.harborprivacy.com/success'
    else:
        checkout_url = f'https://buy.stripe.com/cNiaEWdMPbdJ6vrbd56kg0k?client_reference_id={job_id}_extend&success_url=https://resume.harborprivacy.com/success'
    
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
def download_cover_letter_by_code(access_code):
    rev = request.args.get('rev')
    jobs = load_jobs()
    for job_id, job in jobs.items():
        if job.get('access_code') == access_code and job.get('type') == 'cover_letter':
            if rev is not None:
                try:
                    rev_idx = int(rev)
                    adjustments = job.get('adjustments', [])
                    if rev_idx < len(adjustments) and adjustments[rev_idx].get('pdf_path'):
                        path = adjustments[rev_idx]['pdf_path']
                        if os.path.exists(path):
                            return send_file(path, as_attachment=True, download_name=f'cover_letter_revision_{rev_idx+1}.pdf')
                except:
                    pass
                return jsonify({'error': 'Revision not found'}), 404
            if job.get('pdf_path') and os.path.exists(job['pdf_path']):
                return send_file(job['pdf_path'], as_attachment=True, download_name='cover_letter.pdf')
            return jsonify({'error': 'PDF not found'}), 404
    return jsonify({'error': 'Invalid code'}), 404

@app.route('/api/coverletter/adjust/<access_code>', methods=['POST'])
def adjust_cover_letter(access_code):
    data = request.json
    instruction = data.get('instruction', '').strip()
    if not instruction:
        return jsonify({'error': 'Instruction required'}), 400

    jobs = load_jobs()
    job = None
    job_id = None
    for jid, j in jobs.items():
        if j.get('access_code') == access_code and j.get('type') == 'cover_letter':
            job = j
            job_id = jid
            break

    if not job:
        return jsonify({'error': 'Invalid code'}), 404

    adj_count = job.get('adjustment_count', 0)
    free_used = job.get('free_adjustment_used', False)

    if adj_count > 0 and not free_used:
        job['free_adjustment_used'] = True
    elif adj_count > 0 and free_used:
        return jsonify({'error': 'paid', 'checkout_url': f'https://buy.stripe.com/eVqbJ0cIL4Pl0730yr6kg0l?client_reference_id={job_id}_adjust_{adj_count}&success_url=https://career.harborprivacy.com/success'}), 402

    try:
        prompt = f"""You are editing a cover letter. Apply ONLY this instruction: {instruction}

Current cover letter:
{job.get('letter_text', '')}

Return ONLY the revised cover letter text. No commentary. No markdown. Keep the same opening and closing format."""

        response = anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        revised_text = response.content[0].text

        pdf_path = f'/tmp/coverletter_{job_id}_rev{adj_count+1}.pdf'
        generate_pdf(revised_text, job['your_name'], pdf_path)

        if 'adjustments' not in job:
            job['adjustments'] = []
        job['adjustments'].append({
            'instruction': instruction,
            'text': revised_text,
            'pdf_path': pdf_path,
            'created_at': datetime.now().isoformat()
        })
        job['adjustment_count'] = adj_count + 1
        if adj_count == 0:
            job['free_adjustment_used'] = True
        save_jobs(jobs)

        return jsonify({'status': 'done', 'revised_text': revised_text, 'revision_index': adj_count})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/coverletter/resend/<access_code>', methods=['POST'])
def resend_cover_letter(access_code):
    jobs = load_jobs()
    for job_id, job in jobs.items():
        if job.get('access_code') == access_code and job.get('type') == 'cover_letter':
            try:
                send_cover_letter_email(job, note='You requested a resend of your cover letter.')
                return jsonify({'status': 'sent'})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'Invalid code'}), 404

@app.route('/api/coverletter/status/<access_code>', methods=['GET'])
def coverletter_status(access_code):
    jobs = load_jobs()
    for job_id, job in jobs.items():
        if job.get('access_code') == access_code and job.get('type') == 'cover_letter':
            delete_at = datetime.fromisoformat(job['delete_at'])
            time_remaining = max(0, int((delete_at - datetime.now()).total_seconds()))
            revisions = job.get('adjustments', [])
            return jsonify({
                'status': job.get('status'),
                'letter_text': job.get('letter_text', ''),
                'your_name': job.get('your_name', ''),
                'time_remaining': time_remaining,
                'extended': job.get('extended', False),
                'adjustment_count': job.get('adjustment_count', 0),
                'free_adjustment_used': job.get('free_adjustment_used', False),
                'revision_count': len(revisions),
                'tone': job.get('tone', 'professional'),
                'length': job.get('length', 'standard')
            })
    return jsonify({'error': 'Invalid code'}), 404

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


@app.route('/api/session/<session_id>', methods=['GET'])
def lookup_session(session_id):
    """Look up job by Stripe session ID"""
    jobs = load_jobs()
    
    for job_id, job in jobs.items():
        if job.get('stripe_session') == session_id:
            return jsonify({'job_id': job_id, 'status': job.get('status'), 'type': job.get('type'), 'has_pdf': bool(job.get('revised_pdf_path')), 'feedback': job.get('feedback', ''), 'time_remaining': max(0, int((datetime.fromisoformat(job['delete_at']) - datetime.now()).total_seconds())) if job.get('delete_at') else 0}), 200
    
    return jsonify({'error': 'Not found yet'}), 404

@app.route('/webhook/stripe', methods=['POST'])
@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        import stripe
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
        
        # Try cover letter webhook secret first
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET'))
        except:
            # Try resume webhook secret
            event = stripe.Webhook.construct_event(payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET_RESUME'))
        
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            client_ref = session['client_reference_id'] if hasattr(session, 'client_reference_id') and session['client_reference_id'] else ''
            
            if '_adjust_' in client_ref:
                parts = client_ref.split('_adjust_')
                job_id = parts[0]
                jobs = load_jobs()
                if job_id in jobs:
                    jobs[job_id]['adjustment_paid'] = True
                    jobs[job_id]['free_adjustment_used'] = False  # Reset so next call goes through
                    save_jobs(jobs)
            elif '_extend' in client_ref:
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
                    jobs[client_ref]['stripe_session'] = session['id']
                    save_jobs(jobs)
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        print(f"Webhook error: {e}")
        import traceback
        traceback.print_exc()
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

def send_cover_letter_email(job, subject_override=None, note=None):
    download_url = f"https://career.harborprivacy.com/api/coverletter/download/{job['access_code']}"
    revisions = job.get('adjustments', [])
    revision_links = ''
    for i, rev in enumerate(revisions):
        revision_links += f'<p style="font-family:sans-serif;"><strong>Revision {i+1} Download:</strong><br><a href="https://career.harborprivacy.com/api/coverletter/download/{job["access_code"]}?rev={i}">Click here to download revision {i+1}</a></p>'
    
    note_html = f'<p style="font-family:sans-serif; background:#f0fdf4; padding:12px; border-left:4px solid #00e5c0;">{note}</p>' if note else ''
    
    html_content = f"""
    <h2 style="font-family:sans-serif;">Your Cover Letter is Ready</h2>
    <p style="font-family:sans-serif;">Use the code below to access your cover letter online. Your session will time out after 10 minutes of viewing.</p>
    {note_html}
    <div style="background:#111618;color:#ffffff;font-size:36px;font-weight:bold;letter-spacing:12px;text-align:center;padding:30px;margin:20px 0;font-family:monospace;">
        {job['access_code']}
    </div>
    <p style="font-family:sans-serif;"><strong>Enter this code at:</strong><br>
    <a href="https://career.harborprivacy.com/success">https://career.harborprivacy.com/success</a></p>
    <p style="font-family:sans-serif;"><strong>Download your cover letter (PDF):</strong><br><a href="{download_url}">Click here to download original</a></p>
    {revision_links}
    <p style="margin-top:30px;color:#666;font-size:12px;font-family:sans-serif;">Your viewing session expires after 10 minutes. Re-enter your code to start a new session. Your data is deleted 2 hours after payment.</p>
    """
    
    try:
        with open(job['pdf_path'], 'rb') as f:
            pdf_content = f.read()
        
        resend.Emails.send({
            "from": "Harbor Privacy Cover Letters <coverletter@mail.harborprivacy.com>",
            "to": [job['email']],
            "subject": subject_override or "Your Cover Letter from Harbor Privacy",
            "html": html_content
        })
    except Exception as e:
        print(f"Email send failed: {e}")

def send_resume_review_email(job):
    access_url = "https://resume.harborprivacy.com/success"
    
    has_pdf = bool(job.get('revised_pdf_path'))
    download_url = f"https://resume.harborprivacy.com/api/resume/download/{job['access_code']}"
    html_content = f"""
    <h2 style="font-family: sans-serif;">Your Resume Review is Ready</h2>
    <p style="font-family: sans-serif;">Use the code below to access your results. Your session will time out after 10 minutes of viewing.</p>
    <div style="background: #111618; color: #ffffff; font-size: 36px; font-weight: bold; letter-spacing: 12px; text-align: center; padding: 30px; margin: 20px 0; font-family: monospace;">
        {job['access_code']}
    </div>
    <p style="font-family: sans-serif;"><strong>Enter this code at:</strong><br>
    <a href="https://resume.harborprivacy.com/success">https://resume.harborprivacy.com/success</a></p>
    {('<p style="font-family: sans-serif;"><strong>Download your revised resume PDF:</strong><br><a href="' + download_url + '">Click here to download</a></p>') if has_pdf else ''}
    <p style="margin-top: 30px; color: #666; font-size: 12px; font-family: sans-serif;">Your viewing session expires after 10 minutes. You can re-enter your code to start a new session. Your data is deleted 2 hours after payment.</p>
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
