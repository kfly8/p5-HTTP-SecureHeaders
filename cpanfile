requires 'perl', '5.008001';

on 'test' => sub {
    requires 'Test::More', '0.98';
    requires 'Test::Requires', '0.06';
    requires 'Module::Build::Tiny', '0.035';
};

