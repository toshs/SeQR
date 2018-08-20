import qrcode
import numpy as np
import sys
import random
from PIL import ImageChops
from PIL import Image

from filter import BayerFilter
from constants import W, K
from math import log

class SeQR:

    def __init__(self, 
                url = "http://example.com",
                threthold=30,
                version=1, 
                error_correction=qrcode.constants.ERROR_CORRECT_L, 
                box_size=20,
                border=4,
                color="#888888"
    ):
        self.url = url
        self.threthold = threthold
        self.version = version
        self.error_correction = error_correction
        self.box_size = box_size
        self.border = border

        self.qr = qrcode.QRCode(version=version, 
            error_correction=error_correction, 
            box_size=box_size, 
            border=border
        )
        self.qr.add_data(url)
        self.qr.make()

        print(self.qr.data_cache)
        self.data = self.qr.data_cache
        self.qr_image = self.qr.make_image(fill_color=color, back_color="white")
        self.qr_matrix = np.array(self.qr.get_matrix())
        #self.diff_matrix = None    # Difference between targetQR and maliciouQR with XOR
        
        self.possible_error = self.calc_error_symbol()
        self.sq = self.randomize()
        self.randomized_image = self.sq.make_image(fill_color=color, back_color="white")

    def set_pixel(self, pixel, x, y):
        #offset = self.qr.box_size * self.qr.border
        offset = 0
        x = x * self.qr.box_size
        y = y * self.qr.box_size
        self.randomized_image.paste(pixel, (offset+x,offset+y))

    def get_positions(self):
        return np.where(np.logical_not(self.qr_matrix))

    def make_array(self, text):
        q = qrcode.QRCode(version=self.version, 
            error_correction=self.error_correction, 
            box_size=self.box_size, 
            border=self.border
        )

        q.add_data(text)
        q.make()
        return np.array(q.get_matrix())

    # This function is for Attacking QR
    def calc_possible(self, n):
        if n > 2**8:
            return []
        possible_bit = []
        for i in range(8):
            tail = n>>i & 1
            if tail == 0:
                possible_bit.append(i)
            else:
                pass
        return possible_bit

    def calc_error_symbol(self):
        symbol_num = len(self.data)
        # This function being now developped. So the value is fixed to 15 for level_H.
        return 14

        if self.error_correction == qrcode.constants.ERROR_CORRECT_L:
            return int(symbol_num * 0.07)
        elif self.error_correction == qrcode.constants.ERROR_CORRECT_M:
            return int(symbol_num * 0.15)
        elif self.error_correction == qrcode.constants.ERROR_CORRECT_Q:
            return int(symbol_num * 0.25)
        elif self.error_correction == qrcode.constants.ERROR_CORRECT_H:
            return int(symbol_num * 0.30)

    def randomize(self):
        for i in range(self.possible_error):
            while True:
                r = random.randint(0, 1<<8)
                if self.data[i] != r:
                    self.data[i] = r
                    break
        qr = self.make_qr_from_data(self.data)
        return qr

    def make_qr(self, text):
        qr = qrcode.QRCode(version=self.version, 
            error_correction=self.error_correction, 
            box_size=self.box_size, 
            border=self.border
        )
        qr.add_data(text)
        qr.make()
        return qr

    def make_qr_from_data(self, data):
        qr = self.make_qr(self.url)
        qr.mask_pattern = qr.best_mask_pattern()
        qr.data_cache = data
        for r, row in enumerate(qr.modules):
            for c, col in enumerate(row):
                qr.modules[r][c] = None
        qr.makeImpl(False, qr.mask_pattern)
        return qr


def error_parse(level):
    if level == "L": return qrcode.constants.ERROR_CORRECT_L
    elif level == "M": return qrcode.constants.ERROR_CORRECT_M
    elif level == "Q": return qrcode.constants.ERROR_CORRECT_Q
    elif level == "H": return qrcode.constants.ERROR_CORRECT_H
    else: raise ValueError

def meta_area(sq):
    border = sq.border
    matrix = sq.qr_matrix
    height = len(matrix)
    width = len(matrix[0])
    
    exclusion = []
    "exclude border area"
    for h in range(height):
        for w in range(width):
            if border <= h < height-border and border <= w < width - border:
                hh = h - border
                hh_end = height - 2 * border
                ww = w - border
                ww_end = width - 2 * border
                if (hh < 9 and ww < 9) or (hh >= hh_end - 8 and ww <= 8) or (hh <= 8 and ww >= ww_end - 8):
                    exclusion.append((h, w))
                elif hh == 6 or ww == 6:
                    exclusion.append((h, w))
                elif hh_end-5-5 < hh < hh_end-5 and ww_end-4-5 < ww < ww_end-4:
                    exclusion.append((h, w))                    
            else:
                exclusion.append((h, w))

    return exclusion


if __name__ == '__main__':
    # Get Time
    from time import gmtime, strftime
    T = strftime('%Y%m%d%H%M%S', gmtime())

    if len(sys.argv) < 2:
        print("usage: python3 secure_qr.py <url>")
        sys.exit()
    url = sys.argv[1]

    # Generate Secure QR
    sq = SeQR(url=url, version=2 ,box_size=40 ,error_correction=error_parse("H"))
    sq.qr_image.save("output_image/seQR/"+ T +".png")
    sq.randomized_image.save("output_image/seQR/"+ T +"_w.png")

    # print(list(map(lambda x: hex(x)[2:], sq.qr.data_cache)))
    print(list(map(lambda x: hex(x)[2:], sq.sq.data_cache)))

    # Generate Bayer Pattern
    S = np.array([255,255,255])//4*3
    f = BayerFilter(sq.qr.box_size//2, sq.qr.box_size//2)
    f.pix = np.array(
        [[W, K],
        [K, K]]
    )
    f.makeBayerFilter()
    f.makeImage()
    pixel = f.image

    # Set Pattern to Image
    white_pixel = np.where(~np.array(sq.sq.get_matrix()))
    tx, ty = 0, 0
    for x, y in zip(white_pixel[0], white_pixel[1]):
        if x > 12 and y > 12:
            tx, ty = x, y
            break

    sq.set_pixel(pixel, tx, ty)

    # Save SeQR Image
    sq.randomized_image.save("output_image/seQR/"+ T +"_s.png")

