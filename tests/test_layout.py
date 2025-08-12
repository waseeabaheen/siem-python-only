import os

def test_layout():
 assert os.path.exists(os.path.join(os.path.dirname(__file__),'..','scripts','generate_logs.py'))
