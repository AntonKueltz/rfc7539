from distutils.core import setup, Extension, Command


class TestCommand(Command):
    user_options = []
    description = "Run all tests"

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        from subprocess import call
        call(['python', '-m', 'chacha20poly1305.test'])

_poly1305 = Extension(
    'chacha20poly1305._poly1305',
    include_dirs=['src/'],
    sources=['src/_poly1305.c'],
    extra_compile_args=['-std=c99', '-O2']
)

setup(
    name='chacha20poly1305',
    version='0.0.1',
    author='Anton Kueltz',
    author_email='kueltz.anton@gmail.com',
    license='GNU General Public License v3 (GPLv3)',
    keywords='poly1305 chacha20 chacha20poly1305',
    # description='',
    # long_description=''.join(open('README.rst', 'r').readlines()),
    # url='https://github.com/AntonKueltz/',
    packages=['chacha20poly1305'],
    ext_modules=[_poly1305],
    cmdclass={'test': TestCommand},
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 2',
        # 'Programming Language :: Python :: 3',
    ],
)
