# TradeHub

مشروع ويب بسيط مبني على Flask مع صفحات HTML ثابتة. يحتوي هذا المشروع على واجهة (index.html, auth.html, market.html) وخادم بايثون `app.py` لتقديم الصفحات وواجهات API للتسجيل/الدخول وإدارة المنتجات.

## المتطلبات
- Python 3.10+
- pip

## التثبيت (Windows/PowerShell)
1) (اختياري) إنشاء بيئة افتراضية:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
2) تثبيت المتطلبات:
```powershell
pip install -r requirements.txt
```

## التشغيل محليًا
- تعيين مفتاح الجلسة (مهم للأمان):
```powershell
$env:FLASK_SECRET_KEY = "change-this-please"
```
- تشغيل الخادم:
```powershell
python app.py
```
- افتح المتصفح: `http://localhost:8000/`

## بنية المشروع
- `app.py`: خادم Flask يعرض الصفحات ويقدم واجهات API للمستخدمين والمنتجات
- `index.html`, `auth.html`, `market.html`: واجهة المستخدم
- `data.json`: تخزين المستخدمين (محلي/للتطوير)
- `products.json`: تخزين المنتجات (محلي/للتطوير)
- `image/`: الصور والأصول

ملاحظة: ملفات JSON الحالية للتطوير المحلي فقط، وليست للإنتاج.

## التحضير للرفع إلى GitHub
1) تأكد من وجود الملفات:
   - `.gitignore` لمنع رفع ملفات البيئة والملفات المؤقتة
   - `.gitattributes` لتوحيد نهايات الأسطر
   - هذا `README.md`
2) أوامر Git (استبدل `<YOUR-REPO-URL>` برابط المستودع):
```powershell
git init
git add .
git commit -m "Initial commit: TradeHub"
git branch -M main
git remote add origin <YOUR-REPO-URL>
git push -u origin main
```

## النشر
لأن المشروع يحتوي على خادم Flask، لا يمكن نشره عبر GitHub Pages فقط. استخدم خدمة استضافة تطبيقات مثل Render أو Railway أو Fly.io.

مثال سريع على Render:
- اربط مستودع GitHub
- أمر التشغيل: `python app.py`
- متغير البيئة: `FLASK_SECRET_KEY`

## الترخيص
استخدم هذا المشروع لأغراض شخصية/تجريبية. حدّث هذا القسم حسب حاجتك.
