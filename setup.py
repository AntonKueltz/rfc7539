from setuptools import setup, Extension, Command


class TestCommand(Command):
    user_options = []
    description = "Run all tests"

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        from subprocess import call
        call(['python', '-m', 'rfc7539.test'])


_chacha20 = Extension(
    'rfc7539._chacha20',
    include_dirs=['src/'],
    sources=['src/_chacha20.c'],
    extra_compile_args=['-std=c99', '-O2']
)

_poly1305 = Extension(
    'rfc7539._poly1305',
    include_dirs=['src/'],
    sources=['src/_poly1305.c'],
    extra_compile_args=['-std=c99', '-O2']
)

setup(
    name='rfc7539',
    version='1.2.1',
    author='Anton Kueltz',
    author_email='kueltz.anton@gmail.com',
    license='GNU General Public License v3 (GPLv3)',
    keywords='rfc7539 poly1305 chacha20 chacha20poly1305',
    description='An AEAD construction per RFC7539',
    long_description=''.join(open('README.rst', 'r').readlines()),
    url='https://github.com/AntonKueltz/rfc7539',
    packages=['rfc7539'],
    ext_modules=[_chacha20, _poly1305],
    cmdclass={'test': TestCommand},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
