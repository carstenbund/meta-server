import os
import logging
from MyLogger import Logger
from PIL import Image, UnidentifiedImageError

# Create a logger instance
log = Logger(log_name='thumbs', log_level=logging.DEBUG).get_logger()



def create_thumbnail(input_path, output_directory, size=(256, 256)):
    base_name, ext = os.path.splitext(os.path.basename(input_path))
    webp_output_path = os.path.join(output_directory, f"{base_name}.webp")
    png_output_path = os.path.join(output_directory, f"{base_name}.png")
    
    # Check if the WebP or PNG thumbnail already exists
    if os.path.exists(webp_output_path):
        log.info(f"WebP thumbnail already exists at: {webp_output_path}")
        return webp_output_path
    elif os.path.exists(png_output_path):
        log.info(f"PNG thumbnail already exists at: {png_output_path}")
        return png_output_path
    
    try:
        with Image.open(input_path) as img:
            img.thumbnail(size)
            img.save(webp_output_path, "WEBP")
            log.info(f"Thumbnail created for {input_path} at {webp_output_path}")
            return webp_output_path
    except Exception as e:
        log.error(f"Error creating thumbnail for {input_path}: {e}")
        log.debug(f"Falling back to PNG for: {input_path} due to: {e}")
    
    try:
        with Image.open(input_path) as img:
            img.thumbnail(size)
            img.save(png_output_path, "PNG")
            log.info(f"Thumbnail created for {input_path} at {png_output_path}")
        return png_output_path
    except Exception as e:
        log.error(f"Failed to create thumbnail for: {input_path} due to: {e}")
        return None

def process_directory_tree(input_directory, output_directory):
    for root, dirs, files in os.walk(input_directory):
        for file in files:
            if file.lower().endswith(('.bmp', '.tiff', '.egg', '.png', '.jpg', '.jpeg')):
                input_path = os.path.join(root, file)
                relative_path = os.path.relpath(root, input_directory)
                output_dir = os.path.join(output_directory, relative_path)
                os.makedirs(output_dir, exist_ok=True)
                log.debug(f"Processing file: {input_path}")
                create_thumbnail(input_path, output_dir)

# Example usage
input_directory = "/win95/mcrlnsalg"
output_directory = "thumbnails"
os.makedirs(output_directory, exist_ok=True)
process_directory_tree(input_directory, output_directory)

