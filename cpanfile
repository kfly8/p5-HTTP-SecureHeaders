requires 'perl', '5.008001';
requires 'Carp';

on 'test' => sub {
    requires 'Test::More', '0.98';
    requires 'Module::Build::Tiny', '0.035';
};

