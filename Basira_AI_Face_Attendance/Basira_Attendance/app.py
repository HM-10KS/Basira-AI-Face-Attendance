"""Run the free, local attendance app. No hosted service is used."""
import argparse
import os
import socket
import sys
import threading
import webbrowser
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description='Basira AI — Local Face Attendance')
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--no-browser',action='store_true')
    parser.add_argument('--data-dir',type=Path)
    args=parser.parse_args()
    root=Path(getattr(sys,'_MEIPASS',Path(__file__).resolve().parent))
    default_dir=Path(os.environ.get('LOCALAPPDATA',str(Path.home()))) / 'BasiraAttendance'
    data=args.data_dir or default_dir
    try:
        from basira.web import create_app
        app=create_app(root,data)
    except ImportError:
        print('Please run Setup_Windows.cmd first. Dependencies are not installed.')
        return 1
    if not 1024<=args.port<=65535:
        print('Port must be between 1024 and 65535.')
        return 1
    with socket.socket() as test:
        try:
            test.bind(('127.0.0.1',args.port))
        except OSError:
            print('Port is busy. Close the other Basira window or use --port 8766.')
            return 1
    url=f'http://127.0.0.1:{args.port}'
    print(f'Basira AI: {url}\nData: {data}\nKeep this window open. Press Ctrl+C to stop.')
    if not args.no_browser:
        timer=threading.Timer(1,lambda:webbrowser.open(url))
        timer.daemon=True
        timer.start()
    # Intentionally restricted to this computer. Do not expose Flask's
    # development server to a LAN or the public Internet.
    app.run(host='127.0.0.1',port=args.port,debug=False,use_reloader=False,threaded=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
