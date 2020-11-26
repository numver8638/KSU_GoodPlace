import sass

def compile_sass():
    sass.compile(dirname=('web/static/sass', 'web/static'), output_style='compressed')

if __name__ == '__main__':
    compile_sass()