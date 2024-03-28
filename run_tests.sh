# check to see if there's a app.cfg file in the src/instance directory
if [ -f src/instance/app.cfg ]; then
    mv src/instance/app.cfg src/instance/app.default.cfg
fi

# copy the test/config/app.cfg file to the src/instance directory
cp test/config/app.cfg src/instance/app.cfg
mkdir test/temp

# run the tests
pytest -W ignore::DeprecationWarning

# return the config files back to their original state
rm src/instance/app.cfg
if [ -f src/instance/app.default.cfg ]; then
    mv src/instance/app.default.cfg src/instance/app.cfg
fi