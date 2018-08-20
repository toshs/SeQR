from PIL import Image
import numpy as np
from constants import R, G, B, W, K
from scipy import signal

class BayerFilter:
    # R = np.array([255,0,0])
    # G = np.array([0,255,0])
    # B = np.array([0,0,255])
    # K = np.array([0,0,0])
    # W = np.array([255,255,255])

    pix = np.array(
        [[R, G],
        [G, B]]
    )

    pix_r = np.array(
        [[G, R],
        [B, G]]
    )

    def __init__(self, width=100, height=100, phase=1):
        self.width = width
        self.height = height
        self.phase = phase

        self.bayerfilter = None
        self.image = None

    def show(self):
        try:
            self.image.show()
        except:
            print("please makeImage() before show()")

    def zoom(self, n):
        self.width *= n
        self.height *= n
        self.image = self.image.resize((self.width,self.height), resample=Image.BOX)

    def makeImage(self):
        self.image = Image.fromarray(np.uint8(self.bayerfilter)).convert('RGB')

    def makeBayerFilter(self):
        if self.phase == 1:
            bayerfilter = self.pix
        else:
            bayerfilter = self.pix_r

        bayerfilter = self._hstack(bayerfilter, self.width)
        bayerfilter = self._vstack(bayerfilter, self.height)

        self.bayerfilter = bayerfilter

    def _vstack(self, array, w):
        if w == 1:
            return array
        
        if w % 2 == 0:
            half = self._vstack(array, w//2)
            return np.vstack((half, half))
        else:
            return np.vstack((self._vstack(array, w-1), array))
            
    def _hstack(self, array, w):
        if w == 1:
            return array
        
        if w % 2 == 0:
            half = self._hstack(array, w//2)
            return np.hstack((half, half))
        else:
            return np.hstack((self._hstack(array, w-1), array))

    def demosaic(self):
        r = np.delete(self.bayerfilter, [1,2], 2).reshape(self.width*2, self.height*2)
        g = np.delete(self.bayerfilter, [0,2], 2).reshape(self.width*2, self.height*2)
        b = np.delete(self.bayerfilter, [0,1], 2).reshape(self.width*2, self.height*2)
        print(r)
        f = [
            [1/9,1/9,1/9],
            [1/9,1/9,1/9],
            [1/9,1/9,1/9]
        ]
        rnew = signal.convolve2d(r, np.array(f), 'same')
        gnew = signal.convolve2d(g, np.array(f), 'same')
        bnew = signal.convolve2d(b, np.array(f), 'same')

        rnew = rnew[:, :, np.newaxis]
        gnew = gnew[:, :, np.newaxis]
        bnew = bnew[:, :, np.newaxis]
        
        self.bayerfilter = np.concatenate((rnew, gnew, bnew), axis=2)

if __name__ == '__main__':
    f = BayerFilter(50, 50)
    f.pix = np.array(
        [[W, K],
        [K, K]]
    )
    f.makeBayerFilter()
    f.makeImage()
    f.show()
    f.image.save('output_image/kw.png')