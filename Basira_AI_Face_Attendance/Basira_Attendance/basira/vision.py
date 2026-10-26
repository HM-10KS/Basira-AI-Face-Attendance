"""Lazy loading keeps administration usable when models are not installed."""
import base64
import hashlib
import json
import threading
import time
from pathlib import Path
from .core import normalize


class FaceEngine:
    def __init__(self, model_dir):
        self.model_dir = Path(model_dir)
        self.lock = threading.RLock()
        self.cv = self.np = self.detector = self.recognizer = None
        self.error = "لم يتم تحميل محرك الوجوه بعد"

    def status(self):
        return {'ready': self.detector is not None, 'message': self.error}

    def load(self):
        with self.lock:
            if self.detector is not None:
                return
            try:
                import cv2
                import numpy
                manifest = json.loads((self.model_dir / 'manifest.json').read_text('utf-8'))
                for item in manifest:
                    file = self.model_dir / item['filename']
                    if not file.exists() or hashlib.sha256(file.read_bytes()).hexdigest() != item['sha256']:
                        raise ValueError("نماذج الذكاء الاصطناعي غير مكتملة. شغّل Setup_Windows.cmd أولًا")
                detector = cv2.FaceDetectorYN.create(str(self.model_dir / manifest[0]['filename']), '', (640,480), 0.85,0.3,100)
                recognizer = cv2.FaceRecognizerSF.create(str(self.model_dir / manifest[1]['filename']), '')
                self.cv,self.np,self.detector,self.recognizer = cv2,numpy,detector,recognizer
                self.error = "المحرك جاهز — المعالجة محلية"
            except (ImportError, OSError) as exc:
                self.error = "المكتبات غير مثبتة. شغّل Setup_Windows.cmd أولًا"
                raise ValueError(self.error) from exc
            except Exception as exc:
                self.detector = self.recognizer = None
                self.error = str(exc) if isinstance(exc,ValueError) else "تعذّر تشغيل نموذج الوجوه؛ راجع دليل التشغيل"
                raise ValueError(self.error) from exc

    def extract(self, data_url):
        self.load()
        if not isinstance(data_url,str) or not data_url.startswith('data:image/jpeg;base64,'):
            raise ValueError("الصورة المطلوبة يجب أن تكون JPEG")
        try:
            raw = base64.b64decode(data_url.split(',',1)[1], validate=True)
        except Exception as exc:
            raise ValueError("بيانات الصورة غير صالحة") from exc
        if len(raw) > 1_200_000:
            raise ValueError("الصورة كبيرة جدًا")
        with self.lock:
            cv,np = self.cv,self.np
            image = cv.imdecode(np.frombuffer(raw,dtype=np.uint8),cv.IMREAD_COLOR)
            if image is None or max(image.shape[:2]) > 1920:
                raise ValueError("أبعاد الصورة غير صالحة؛ الحد الأقصى 1920 بكسل")
            started = time.perf_counter()
            h,w = image.shape[:2]
            self.detector.setInputSize((w,h))
            _, faces = self.detector.detect(image)
            result = {'width':w,'height':h,'faces':[],'feature':None}
            if faces is None:
                result['message'] = 'لم يتم اكتشاف وجه'
                return result
            result['faces'] = [{'box':[float(v) for v in f[:4]],'detection_score':float(f[-1])} for f in faces]
            if len(faces) != 1:
                result['message'] = 'يجب أن يقف شخص واحد أمام الكاميرا'
                return result
            face = faces[0]
            x,y,bw,bh = [int(v) for v in face[:4]]
            x1,y1,x2,y2 = max(x,0),max(y,0),min(x+bw,w),min(y+bh,h)
            crop = image[y1:y2,x1:x2]
            if min(bw,bh) < 80 or crop.size == 0 or x < 0 or y < 0 or x+bw > w or y+bh > h:
                result['message'] = 'اقترب قليلًا وضع الوجه كاملًا داخل الإطار'
                return result
            gray = cv.cvtColor(crop,cv.COLOR_BGR2GRAY)
            blur,brightness = float(cv.Laplacian(gray,cv.CV_64F).var()),float(gray.mean())
            result['quality'] = {'sharpness':round(blur,1),'brightness':round(brightness,1)}
            if blur < 35 or not 35 < brightness < 225:
                result['message'] = 'حسّن الإضاءة وثبّت الوجه أمام الكاميرا'
                return result
            aligned = self.recognizer.alignCrop(image,face)
            feature = self.recognizer.feature(aligned).flatten().tolist()
            result['feature'] = normalize(feature)
            result['latency_ms'] = round((time.perf_counter()-started)*1000,1)
            result['message'] = 'وجه واضح'
            return result
