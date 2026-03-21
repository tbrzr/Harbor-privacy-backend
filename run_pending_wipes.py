#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/ubuntu/harbor-backend')
exec(compile(open('/home/ubuntu/harbor-backend/webhook.py').read().split('if __name__')[0], 'webhook.py', 'exec'))
process_pending_wipes()
