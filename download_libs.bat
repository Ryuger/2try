@echo off
echo Downloading local libraries for monitoring application...

REM Create directories
mkdir static\libs\css 2>nul
mkdir static\libs\js 2>nul
mkdir static\libs\fonts 2>nul

echo.
echo Downloading Bootstrap 5.3.0...
curl -L -o static\libs\css\bootstrap.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css
curl -L -o static\libs\js\bootstrap.bundle.min.js https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js

echo.
echo Downloading Chart.js 4.3.0...
curl -L -o static\libs\js\chart.min.js https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.min.js

echo.
echo Downloading Font Awesome 6.4.0...
curl -L -o static\libs\css\fontawesome.min.css https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css

echo.
echo Downloading Feather Icons 4.29.0...
curl -L -o static\libs\js\feather.min.js https://cdn.jsdelivr.net/npm/feather-icons@4.29.0/dist/feather.min.js

echo.
echo Downloading jQuery 3.7.0...
curl -L -o static\libs\js\jquery.min.js https://code.jquery.com/jquery-3.7.0.min.js

echo.
echo All libraries downloaded successfully!
echo Files saved in static\libs\ directory
pause
