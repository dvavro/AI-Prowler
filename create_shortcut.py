#!/usr/bin/env python3
"""
RAG Icon Generator and Shortcut Creator
Creates Windows icon and desktop shortcut
"""

import os
import sys
from pathlib import Path

def create_ico_from_svg():
    """Convert SVG to ICO file using PIL/Pillow"""
    try:
        from PIL import Image
        from io import BytesIO
        
        # Try to use cairosvg for better SVG rendering
        try:
            import cairosvg
            
            # Read SVG
            svg_path = Path(__file__).parent / "rag_icon.svg"
            
            if not svg_path.exists():
                print("⚠️  SVG icon not found, skipping icon creation")
                return False
            
            # Convert SVG to PNG at multiple sizes for ICO
            ico_path = Path(__file__).parent / "rag_icon.ico"
            
            sizes = [16, 32, 48, 64, 128, 256]
            images = []
            
            for size in sizes:
                png_data = cairosvg.svg2png(
                    url=str(svg_path),
                    output_width=size,
                    output_height=size
                )
                img = Image.open(BytesIO(png_data))
                images.append(img)
            
            # Save as ICO
            images[0].save(
                str(ico_path),
                format='ICO',
                sizes=[(img.width, img.height) for img in images],
                append_images=images[1:]
            )
            
            print(f"✅ Created icon: {ico_path}")
            return True
            
        except ImportError:
            # Fallback: Create simple colored icon without cairosvg
            print("ℹ️  cairosvg not available, creating simple icon...")
            
            ico_path = Path(__file__).parent / "rag_icon.ico"
            
            # Create simple colored icons
            sizes = [16, 32, 48, 64, 128, 256]
            images = []
            
            for size in sizes:
                # Create dark blue square with "RAG" text
                img = Image.new('RGBA', (size, size), (26, 26, 46, 255))
                images.append(img)
            
            # Save as ICO
            images[0].save(
                str(ico_path),
                format='ICO',
                sizes=[(img.width, img.height) for img in images],
                append_images=images[1:]
            )
            
            print(f"✅ Created simple icon: {ico_path}")
            return True
            
    except ImportError:
        print("⚠️  PIL/Pillow not available, skipping icon creation")
        return False
    except Exception as e:
        print(f"⚠️  Could not create icon: {e}")
        return False

def create_desktop_shortcut():
    """Create desktop shortcut to RAG"""
    try:
        import winshell
        from win32com.client import Dispatch
        
        desktop = winshell.desktop()
        shortcut_path = os.path.join(desktop, "RAG.lnk")
        
        # Get paths
        install_dir = Path(__file__).parent
        target = str(install_dir / "RAG_RUN.bat")
        icon_path = str(install_dir / "rag_icon.ico")
        
        # Create shortcut
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.TargetPath = target
        shortcut.WorkingDirectory = str(install_dir)
        shortcut.Description = "RAG - Personal AI Knowledge Base"
        
        # Set icon if it exists
        if os.path.exists(icon_path):
            shortcut.IconLocation = icon_path
        
        shortcut.save()
        
        print(f"✅ Created desktop shortcut: {shortcut_path}")
        return True
        
    except ImportError:
        print("⚠️  winshell/pywin32 not available for shortcuts")
        return create_desktop_shortcut_fallback()
    except Exception as e:
        print(f"⚠️  Could not create shortcut with winshell: {e}")
        return create_desktop_shortcut_fallback()

def create_desktop_shortcut_fallback():
    """Create desktop shortcut using PowerShell (no dependencies)"""
    try:
        import subprocess

        # Get paths
        install_dir = Path(__file__).parent
        target = install_dir / "RAG_RUN.bat"
        icon_path = install_dir / "rag_icon.ico"

        # Use Windows Shell API to get real Desktop path (handles OneDrive Desktop)
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "[Environment]::GetFolderPath('Desktop')"],
            capture_output=True, text=True
        )
        desktop = Path(result.stdout.strip()) if result.returncode == 0 and result.stdout.strip() else Path.home() / "Desktop"
        shortcut_path = desktop / "AI Prowler.lnk"

        icon_line = f'$Shortcut.IconLocation = "{icon_path},0"' if icon_path.exists() else ""

        ps_script = f'''
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("{shortcut_path}")
$Shortcut.TargetPath = "{target}"
$Shortcut.WorkingDirectory = "{install_dir}"
$Shortcut.Description = "AI Prowler - Personal AI Knowledge Base"
{icon_line}
$Shortcut.Save()
'''
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True, text=True
        )

        if shortcut_path.exists():
            print(f"✅ Created desktop shortcut: {shortcut_path}")
            return True
        else:
            print(f"⚠️  Could not create shortcut: {result.stderr}")
            return False

    except Exception as e:
        print(f"⚠️  Could not create shortcut: {e}")
        return False

def main():
    """Main entry point"""
    print()
    print("=" * 60)
    print("RAG ICON & SHORTCUT CREATOR")
    print("=" * 60)
    print()
    
    # Create icon
    print("[1/2] Creating icon...")
    icon_created = create_ico_from_svg()
    print()
    
    # Create desktop shortcut
    print("[2/2] Creating desktop shortcut...")
    shortcut_created = create_desktop_shortcut()
    print()
    
    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    if icon_created:
        print("✅ Icon created: rag_icon.ico")
    else:
        print("⚠️  Icon not created (optional)")
    
    if shortcut_created:
        print("✅ Desktop shortcut created")
        print()
        print("You can now launch RAG from your desktop!")
    else:
        print("⚠️  Desktop shortcut not created")
        print("   You can still use RAG_RUN.bat from the install folder")
    
    print("=" * 60)
    print()

if __name__ == "__main__":
    main()
